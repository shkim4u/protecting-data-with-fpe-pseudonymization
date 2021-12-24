import * as cdk from '@aws-cdk/core';
import * as iam from '@aws-cdk/aws-iam'
import * as lambda from '@aws-cdk/aws-lambda'
import * as apigatewayv2 from '@aws-cdk/aws-apigatewayv2'
import * as kms from '@aws-cdk/aws-kms'
import * as cognito from '@aws-cdk/aws-cognito'
import * as path from 'path'
import { spawnSync, SpawnSyncOptions } from 'child_process';
import { CfnIntegrationResponse, CorsHttpMethod } from '@aws-cdk/aws-apigatewayv2';
import { LambdaProxyIntegration } from '@aws-cdk/aws-apigatewayv2-integrations';
import * as apiGatewayAuthorizers from '@aws-cdk/aws-apigatewayv2-authorizers';
import { RemovalPolicy } from '@aws-cdk/core';
import { setFlagsFromString } from 'v8';
import { AccountRecovery } from '@aws-cdk/aws-cognito';

function exec(command: string, options?: SpawnSyncOptions) {
	const proc = spawnSync('bash', ['-c', command], options);

	if (proc.error) {
		throw proc.error;
	}

	if (proc.status != 0) {
		if (proc.stdout || proc.stderr) {
			throw new Error(`[Status ${proc.status}] stdout: ${proc.stdout?.toString().trim()}\n\n\nstderr: ${proc.stderr?.toString().trim()}`);
		}
		throw new Error(`go exited with status ${proc.status}`);
	}

	return proc;
}


export class FpePseudonymizationStack extends cdk.Stack {
  constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

		// KMS master key to double-protect FPE encryption key to be stored in Secret Manager as encrypted form.
		const fpeMasterKey = new kms.Key(
			this,
			'fpe-master-key', {
			removalPolicy: cdk.RemovalPolicy.DESTROY,
			// pendingWindow: cdk.Duration.days(7),
			alias: 'alias/fpe-master-key',
			description: 'KMS master key to double-protect FPE encryption key to be stored in Secret Manager as encrypted form.',
			enableKeyRotation: true,
		});

		const asset = path.join(__dirname, "../lambda/fpe");
		const environment = {
			CGO_ENABLED: '0',
			GOOS: 'linux',
			GOARCH: 'amd64',
		};

		// Create Lambda function.
		const fpeLambdaFunction = new lambda.Function(
			this,
			'FpeLambdaFunction',
			{
				code: lambda.Code.fromAsset(
					asset,
					{
						bundling: {
							// Try to bundle on the local machine.
							local: {
								tryBundle(outputDir: string) {
									console.log(`Output Directory: ${outputDir}`);
									// Ensure that all the required dependencies are installed locally.
									try {
										exec(
											'go version',
											{
												stdio: [
													'ignore',					// Ignore stdio.
													process.stderr,		// Redirect stdout to stderr.
													'inherit'					// Inherit stderr.
												],
											}
										);
									} catch {
										// If Go is not installed, then just return false to tell the CDK to attempt bundling with Docker.
										return false;
									}

									exec(
										[
											'go test -v',			// Test first.
											`go build -mod=vendor -o ${path.join(outputDir, 'bootstrap')}`
										].join(' && '),
										{
											env: { ...process.env, ...environment},
											stdio: [
												'ignore', 			// Ignore stdio.
												process.stderr, // Redirect stdout to stderr.
												'inherit' 			// inherit stderr.
											],
											cwd: asset,				// Workding directory to run the build command from.
										},
									);

									return true;
								},
							},
							image: lambda.Runtime.GO_1_X.bundlingImage,
							command: [
								'bash',
								'-c',
								[
									'go test -v',
									'go build -mod=vendor -o /asset-output/bootstrap',
								].join(' && ')
							],
							environment: environment
						},
					}
				),
				// If we name our handler 'bootstrap' we can also use the 'provided' runtime.
				handler: 'bootstrap',
				// handler: 'main',
				runtime: lambda.Runtime.GO_1_X,
				environment: {
					'FPE_MASTER_KEY_ARN': fpeMasterKey.keyArn,
					'FPE_DEK_SECRET_NAME': '/secret/fpe/dek',
					// Tweak value for FPE.
					'FPE_TWEAK': 'D8E7920AFA330A73'
				}
			}
		);

		/**
		 * Permission to create, read, and delete secret value in Secrets Manager to store FPE encryption key encrypted by KMS.
		 * References:
		 * - https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_resource-policies.html
		 * - https://docs.aws.amazon.com/ko_kr/secretsmanager/latest/userguide/reference_iam-permissions.html
		 */
		const lambdaFunctionPermissionPolicy = new iam.PolicyStatement(
			{
				actions: [
					'secretsmanager:CreateSecret',
					'secretsmanager:DeleteSecret',
					'secretsmanager:GetSecretValue'
				],
				resources: ['*'],
				effect: iam.Effect.ALLOW
			}
		);
		// Attach IAM permission policy to this Lambda function.
		fpeLambdaFunction.grantPrincipal.addToPrincipalPolicy(lambdaFunctionPermissionPolicy);
		// Grant encrypt/decrypt to this Lambda.
		fpeMasterKey.grantEncryptDecrypt(fpeLambdaFunction.grantPrincipal);

		/**
		 * [2021-12-07]
		 * Create the user pool and other resources to control access to the API Gateway.
		 */
		// User pool.
		const userPool = new cognito.UserPool(
			this,
			`fpe-userpool`, {
				userPoolName: `fpe-userpool`,
				removalPolicy: cdk.RemovalPolicy.DESTROY,
				selfSignUpEnabled: true,
				signInAliases: {email: true},
				autoVerify: {email: true},
				passwordPolicy: {
					minLength: 8,
					requireLowercase: true,
					requireDigits: true,
					requireUppercase: true,
					requireSymbols: true,
				},
				accountRecovery: cognito.AccountRecovery.EMAIL_ONLY
			}
		);

		// User pool client.
		const userPoolClient = new cognito.UserPoolClient(
			this,
			`fpe-userpool-client`,
			{
				userPool,
				authFlows: {
					adminUserPassword: true,
					userPassword: true,
					custom: true,
					userSrp: true,
				},
				supportedIdentityProviders: [
					cognito.UserPoolClientIdentityProvider.COGNITO,
				],
			}
		);

		// Create the authorizer.
		const authorizer = new apiGatewayAuthorizers.HttpUserPoolAuthorizer(
			{
				userPool,
				userPoolClients: [userPoolClient],
				identitySource: ['$request.header.Authorization'],
			}
		);

		const api = new apigatewayv2.HttpApi(
			this,
			'FpeApi',
			{
				description: 'Format Preserving Pseudonumization API',
				createDefaultStage: true,
				corsPreflight: {
					allowHeaders: [
						'Content-Type',
						'X-Amz-Date',
						'Authorization',
						'X-Api-Key',
					],
					// allowCredentials: true,
					allowMethods: [CorsHttpMethod.POST],
					allowOrigins: ['*']
				}
			}
		);

		api.addRoutes(
			{
				path: '/encrypt',
				integration: new LambdaProxyIntegration(
					{
						handler: fpeLambdaFunction
					}
				),
				methods: [apigatewayv2.HttpMethod.POST],
				authorizer: authorizer										// Authorizer.
			}
		);

		api.addRoutes(
			{
				path: '/decrypt',
				integration: new LambdaProxyIntegration(
					{
						handler: fpeLambdaFunction
					}
				),
				methods: [apigatewayv2.HttpMethod.POST],
				authorizer: authorizer										// Authorizer.
			}
		);

		api.addRoutes(
			{
				path: '/envelope-encrypt',
				integration: new LambdaProxyIntegration(
					{
						handler: fpeLambdaFunction
					}
				),
				methods: [apigatewayv2.HttpMethod.POST],
				authorizer: authorizer
			}
		);

		api.addRoutes(
			{
				path: '/envelope-decrypt',
				integration: new LambdaProxyIntegration(
					{
						handler: fpeLambdaFunction
					}
				),
				methods: [apigatewayv2.HttpMethod.POST],
				authorizer: authorizer
			}
		);

		new cdk.CfnOutput(this, 'FpeMasterKeyArn', {value: fpeMasterKey.keyArn,});
		new cdk.CfnOutput(this, 'ApiUrlOutput', {value: api.url!});
		new cdk.CfnOutput(this, 'UserPoolId', { value: userPool.userPoolId });
		new cdk.CfnOutput(this, 'UserPoolClientId', { value: userPoolClient.userPoolClientId });
  }
}
