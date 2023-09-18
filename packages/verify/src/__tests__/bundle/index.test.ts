import { bundleFromJSON } from '@sigstore/bundle';
import assert from 'assert';
import { toSignedEntity } from '../../bundle';
import { x509Certificate } from '../../x509/cert';
import bundles from '../__fixtures__/bundles/v01';

describe('toSignedEntity', () => {
  describe('when the bundle is a dsseEnvelope', () => {
    const bundle = bundleFromJSON(bundles.dsse.valid.withSigningCert);

    it('returns a SignedEntity', () => {
      const entity = toSignedEntity(bundle);

      expect(entity).toBeDefined();

      assert(entity.key.$case === 'certificate');
      expect(entity.key.certificate).toBeInstanceOf(x509Certificate);

      expect(entity.signature).toBeDefined();
      expect(entity.tlogEntries).toHaveLength(1);
      expect(entity.timestamps).toHaveLength(1);
    });
  });

  describe('when the bundle is a messageSignature', () => {
    const bundle = bundleFromJSON(bundles.signature.valid.withPublicKey);

    it('returns a SignedEntity', () => {
      const entity = toSignedEntity(bundle);

      expect(entity).toBeDefined();

      assert(entity.key.$case === 'public-key');
      expect(entity.key.hint).toBeDefined();

      expect(entity.signature).toBeDefined();
      expect(entity.tlogEntries).toHaveLength(1);
      expect(entity.timestamps).toHaveLength(1);
    });
  });
});
