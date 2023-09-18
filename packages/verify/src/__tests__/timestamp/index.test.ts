import { bundleFromJSON } from '@sigstore/bundle';
import { VerificationError } from '../../error';
import { verifyTLogTimestamp } from '../../timestamp/index';
import { crypto } from '../../util';
import bundles from '../__fixtures__/bundles/v01';
import bundlesv02 from '../__fixtures__/bundles/v02';

import type { TLogAuthority } from '../../trust';

describe('verifyTLogTimestamp', () => {
  // Actual public key for public-good Rekor
  const keyBytes = Buffer.from(
    'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==',
    'base64'
  );
  const keyID = crypto.hash(keyBytes);

  const validTLog: TLogAuthority = {
    logID: keyID,
    publicKey: crypto.createPublicKey(keyBytes),
    validFor: { start: new Date(0), end: new Date('2100-01-01') },
  };

  describe('when a valid bundle with inclusion promise is provided', () => {
    const bundle = bundleFromJSON(bundles.signature.valid.withSigningCert);
    const tlogEntry = bundle.verificationMaterial!.tlogEntries[0];

    it('does NOT throw an error', () => {
      verifyTLogTimestamp(tlogEntry, [validTLog]);
    });
  });

  describe('when a valid bundle with inclusion proof is provided', () => {
    const bundle = bundleFromJSON(bundlesv02.signature.valid.withSigningCert);
    const tlogEntry = bundle.verificationMaterial!.tlogEntries[0];

    it('does NOT throw an error', () => {
      verifyTLogTimestamp(tlogEntry, [validTLog]);
    });
  });

  describe('when a valid bundle with NOT inclusion proof/promise is provided', () => {
    const bundle = bundleFromJSON(bundlesv02.signature.valid.withSigningCert);

    // Manipulate bundle to remove inclusion proof/promise
    const tlogEntry = {
      ...bundle.verificationMaterial?.tlogEntries[0],
      inclusionProof: undefined,
      inclusionPromise: undefined,
    };

    it('throws an error', () => {
      expect(() => verifyTLogTimestamp(tlogEntry, [validTLog])).toThrowWithCode(
        VerificationError,
        'TLOG_MISSING_INCLUSION_ERROR'
      );
    });
  });
});
