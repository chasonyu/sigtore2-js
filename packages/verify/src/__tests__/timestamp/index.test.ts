import { bundleFromJSON } from '@sigstore/bundle';
import { bundleWrapper } from '../../bundle';
import { VerificationError } from '../../error';
import { verifyTimestamps } from '../../timestamp/index';
import { crypto } from '../../util';
import bundles from '../__fixtures__/bundles/v01';
import bundlesv02 from '../__fixtures__/bundles/v02';

import { fromPartial } from '@total-typescript/shoehorn';
import type { TrustMaterial } from '../../shared.types';
import type { TLogAuthority } from '../../trust';

describe('verifyTimestamps', () => {
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

  const trustMaterial = fromPartial<TrustMaterial>({
    tlogs: [validTLog],
  });

  describe('when a valid bundle with inclusion promise is provided', () => {
    const bundle = bundleFromJSON(bundles.signature.valid.withSigningCert);
    const signedEntity = bundleWrapper(bundle);

    it('returns timestamp from the tlog entry', () => {
      const results = verifyTimestamps(signedEntity, trustMaterial);

      expect(results).toHaveLength(1);
      expect(results[0].type).toEqual('transparency-log');
      expect(results[0].logID).toEqual(keyID);
      expect(results[0].timestamp).toEqual(
        new Date(
          Number(bundle.verificationMaterial!.tlogEntries[0].integratedTime) *
            1000
        )
      );
    });
  });

  describe('when a valid bundle with inclusion proof is provided', () => {
    const bundle = bundleFromJSON(bundlesv02.signature.valid.withSigningCert);
    const signedEntity = bundleWrapper(bundle);

    it('returns timestamp from the tlog entry', () => {
      const results = verifyTimestamps(signedEntity, trustMaterial);

      expect(results).toHaveLength(1);
      expect(results[0].type).toEqual('transparency-log');
      expect(results[0].logID).toEqual(keyID);
      expect(results[0].timestamp).toEqual(
        new Date(
          Number(bundle.verificationMaterial!.tlogEntries[0].integratedTime) *
            1000
        )
      );
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
    const signedEntity = bundleWrapper({
      ...bundle,
      verificationMaterial: {
        ...bundle.verificationMaterial,
        tlogEntries: [tlogEntry],
      },
    });

    it('throws an error', () => {
      expect(() =>
        verifyTimestamps(signedEntity, trustMaterial)
      ).toThrowWithCode(VerificationError, 'TLOG_MISSING_INCLUSION_ERROR');
    });
  });
});
