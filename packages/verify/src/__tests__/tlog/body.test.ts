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
import { verifyTLogBody } from '../../tlog/body';
import bundles from '../__fixtures__/bundles/v01';

describe('verifyTLogBody', () => {
  describe('when a message signature bundle is provided', () => {
    describe('when everything is valid', () => {
      const bundle = bundleFromJSON(bundles.signature.valid.withSigningCert);
      const tlogEntry = bundle.verificationMaterial.tlogEntries[0];
      const content = signatureContent(bundle);

      it('does NOT throw an error', () => {
        expect(verifyTLogBody(tlogEntry, content)).toBeUndefined();
      });
    });

    describe('when the signature does NOT match the value in the tlog entry', () => {
      const bundle = bundleFromJSON(
        bundles.signature.invalid.tlogIncorrectSigInBody
      );
      const tlogEntry = bundle.verificationMaterial.tlogEntries[0];
      const content = signatureContent(bundle);

      it('throws an error', () => {
        expect(() => verifyTLogBody(tlogEntry, content)).toThrowWithCode(
          VerificationError,
          'TLOG_BODY_ERROR'
        );
      });
    });

    describe('when the digest does NOT match the value in the tlog entry', () => {
      const bundle = bundleFromJSON(
        bundles.signature.invalid.tlogIncorrectDigestInBody
      );
      const tlogEntry = bundle.verificationMaterial.tlogEntries[0];
      const content = signatureContent(bundle);

      it('throws an error', () => {
        expect(() => verifyTLogBody(tlogEntry, content)).toThrowWithCode(
          VerificationError,
          'TLOG_BODY_ERROR'
        );
      });
    });

    describe('when there is a version mismatch between the tlog entry and the body', () => {
      const bundle = bundleFromJSON(
        bundles.signature.invalid.tlogVersionMismatch
      );
      const tlogEntry = bundle.verificationMaterial.tlogEntries[0];
      const content = signatureContent(bundle);

      it('throws an error', () => {
        expect(() => verifyTLogBody(tlogEntry, content)).toThrowWithCode(
          VerificationError,
          'TLOG_BODY_ERROR'
        );
      });
    });
  });

  describe('when a DSSE Bundle is provided', () => {
    describe('when everything is valid', () => {
      const bundle = bundleFromJSON(bundles.dsse.valid.withSigningCert);
      const tlogEntry = bundle.verificationMaterial.tlogEntries[0];
      const content = signatureContent(bundle);

      it('does NOT throw an error', () => {
        expect(verifyTLogBody(tlogEntry, content)).toBeUndefined();
      });
    });

    describe('when the payload hash does NOT match the value in the intoto entry', () => {
      const bundle = bundleFromJSON(
        bundles.dsse.invalid.badSignatureTLogIntoto
      );
      const tlogEntry = bundle.verificationMaterial.tlogEntries[0];
      const content = signatureContent(bundle);

      it('throws an error', () => {
        expect(() => verifyTLogBody(tlogEntry, content)).toThrowWithCode(
          VerificationError,
          'TLOG_BODY_ERROR'
        );
      });
    });

    describe('when the payload hash does NOT match the value in the dsse entry', () => {
      const bundle = bundleFromJSON(bundles.dsse.invalid.badSignatureTLogDSSE);
      const tlogEntry = bundle.verificationMaterial.tlogEntries[0];
      const content = signatureContent(bundle);

      it('throws an error', () => {
        expect(() => verifyTLogBody(tlogEntry, content)).toThrowWithCode(
          VerificationError,
          'TLOG_BODY_ERROR'
        );
      });
    });

    describe('when the signature does NOT match the value in the intoto entry', () => {
      const bundle = bundleFromJSON(
        bundles.dsse.invalid.tlogIntotoIncorrectSigInBody
      );
      const tlogEntry = bundle.verificationMaterial.tlogEntries[0];
      const content = signatureContent(bundle);

      it('throws an error', () => {
        expect(() => verifyTLogBody(tlogEntry, content)).toThrowWithCode(
          VerificationError,
          'TLOG_BODY_ERROR'
        );
      });
    });

    describe('when the signature does NOT match the value in the dsse entry', () => {
      const bundle = bundleFromJSON(
        bundles.dsse.invalid.tlogDSSEIncorrectSigInBody
      );
      const tlogEntry = bundle.verificationMaterial.tlogEntries[0];
      const content = signatureContent(bundle);

      it('throws an error', () => {
        expect(() => verifyTLogBody(tlogEntry, content)).toThrowWithCode(
          VerificationError,
          'TLOG_BODY_ERROR'
        );
      });
    });

    describe('when the tlog entry version is unsupported', () => {
      const bundle = bundleFromJSON(
        bundles.dsse.invalid.tlogUnsupportedVersion
      );
      const tlogEntry = bundle.verificationMaterial.tlogEntries[0];
      const content = signatureContent(bundle);

      it('throws an error', () => {
        expect(() => verifyTLogBody(tlogEntry, content)).toThrowWithCode(
          VerificationError,
          'TLOG_BODY_ERROR'
        );
      });
    });

    describe('when the signature count does NOT match the intoto entry', () => {
      const bundle = bundleFromJSON(
        bundles.dsse.invalid.tlogIntotoTooManySigsInBody
      );
      const tlogEntry = bundle.verificationMaterial.tlogEntries[0];
      const content = signatureContent(bundle);

      it('throws an error', () => {
        expect(() => verifyTLogBody(tlogEntry, content)).toThrowWithCode(
          VerificationError,
          'TLOG_BODY_ERROR'
        );
      });
    });

    describe('when the signature count does NOT match the dsse entry', () => {
      const bundle = bundleFromJSON(
        bundles.dsse.invalid.tlogDSSETooManySigsInBody
      );
      const tlogEntry = bundle.verificationMaterial.tlogEntries[0];
      const content = signatureContent(bundle);

      it('throws an error', () => {
        expect(() => verifyTLogBody(tlogEntry, content)).toThrowWithCode(
          VerificationError,
          'TLOG_BODY_ERROR'
        );
      });
    });

    describe('when there is a version mismatch between the tlog entry and the body', () => {
      const bundle = bundleFromJSON(bundles.dsse.invalid.tlogVersionMismatch);
      const tlogEntry = bundle.verificationMaterial.tlogEntries[0];
      const content = signatureContent(bundle);

      it('throws an error', () => {
        expect(() => verifyTLogBody(tlogEntry, content)).toThrowWithCode(
          VerificationError,
          'TLOG_BODY_ERROR'
        );
      });
    });
  });

  describe('when a DSSE Bundle w/ dsse tlog entry is provided', () => {
    describe('when everything is valid', () => {
      const bundle = bundleFromJSON(bundles.dsse.valid.withDSSETLogEntry);
      const tlogEntry = bundle.verificationMaterial.tlogEntries[0];
      const content = signatureContent(bundle);

      it('does NOT throw an error', () => {
        expect(verifyTLogBody(tlogEntry, content)).toBeUndefined();
      });
    });
  });
});
