import * as cdk from '@aws-cdk/core';
import * as lambda from '@aws-cdk/aws-lambda'
import * as path from 'path'
// import { exec } from 'child_process';
import { spawnSync, SpawnSyncOptions } from 'child_process';

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

		const asset = path.join(__dirname, "../lambda/fpe");
		const environment = {
			CGO_ENABLED: '0',
			GOOS: 'linux',
			GOARCH: 'amd64',
		};

		// Create Lambda function.
		const lambdaFunction = new lambda.Function(
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
											// `go build -o ${path.join(outputDir, 'bootstrap')}`
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
							image: lambda.Runtime.GO_1_X.bundlingDockerImage,
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
				// handler: 'bootstrap',
				handler: 'main',
				runtime: lambda.Runtime.GO_1_X
			}
		);
  }
}
