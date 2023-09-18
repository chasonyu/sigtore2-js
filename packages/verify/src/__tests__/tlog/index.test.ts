/*
Copyright 2023 The Sigstore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
import { bundleFromJSON } from '@sigstore/bundle';
import { signatureContent } from '../../bundle';
import { VerificationError } from '../../error';
import { verifyTLogBody } from '../../tlog';
import bundles from '../__fixtures__/bundles/v01';

describe('verifyTLogBody', () => {
  describe('when the tlog entry matches', () => {
    const bundle = bundleFromJSON(bundles.signature.valid.withSigningCert);
    const tlogEntry = bundle.verificationMaterial.tlogEntries[0];
    const content = signatureContent(bundle);

    it('does NOT throw an error', () => {
      expect(verifyTLogBody(tlogEntry, content)).toBeUndefined();
    });
  });

  describe('when one of the tlog entry does NOT match', () => {
    const bundle1 = bundleFromJSON(bundles.signature.valid.withSigningCert);
    const content = signatureContent(bundle1);

    const bundle2 = bundleFromJSON(
      bundles.signature.invalid.tlogIncorrectSigInBody
    );
    const tlogEntry = bundle2.verificationMaterial.tlogEntries[0];

    it('throws an error', () => {
      expect(() => verifyTLogBody(tlogEntry, content)).toThrowWithCode(
        VerificationError,
        'TLOG_BODY_ERROR'
      );
    });
  });
});
