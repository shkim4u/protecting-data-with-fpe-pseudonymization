import { expect as expectCDK, matchTemplate, MatchStyle } from '@aws-cdk/assert';
import * as cdk from '@aws-cdk/core';
import * as FpePseudonymization from '../lib/fpe-pseudonymization-stack';

test('Empty Stack', () => {
    const app = new cdk.App();
    // WHEN
    const stack = new FpePseudonymization.FpePseudonymizationStack(app, 'MyTestStack');
    // THEN
    expectCDK(stack).to(matchTemplate({
      "Resources": {}
    }, MatchStyle.EXACT));
});
