#!/bin/bash

# Try this after running API with "sam-beta-cdk local start-api".
# See: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-cdk-testing.html

# FPE Encrypt.
sam-beta-cdk local invoke FpePseudonymizationStack/FpeLambdaFunction --event ./event.json