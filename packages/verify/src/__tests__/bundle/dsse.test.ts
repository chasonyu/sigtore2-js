import type { Envelope } from '@sigstore/bundle';
import crypto from 'crypto';
import { DSSESignatureContent } from '../../bundle/dsse';
import { hash } from '../../util/crypto';

describe('DSSESignatureContent', () => {
  const key = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
  const payload = Buffer.from('payload');
  const payloadType = 'payloadType';
  const pae = Buffer.from(
    `DSSEv1 ${payloadType.length} ${payloadType} ${payload.length} ${payload}`
  );

  const env: Envelope = {
    payload,
    payloadType,
    signatures: [
      {
        sig: crypto.sign(null, pae, key.privateKey),
        keyid: '',
      },
    ],
  };

  const subject = new DSSESignatureContent(env);

  describe('#compareDigest', () => {
    describe('when the digest does NOT match the payload hash', () => {
      it('returns false', () => {
        expect(subject.compareDigest(Buffer.from(''))).toBe(false);
      });
    });

    describe('when the digest matches the payload hash', () => {
      const expectedDigest = hash(env.payload);

      it('returns true', () => {
        expect(subject.compareDigest(expectedDigest)).toBe(true);
      });
    });
  });

  describe('#compareSignature', () => {
    describe('when the signature does NOT match the payload hash', () => {
      it('returns false', () => {
        expect(subject.compareSignature(Buffer.from(''))).toBe(false);
      });
    });

    describe('when the signature matches the payload hash', () => {
      const expectedSignature = env.signatures[0].sig;

      it('returns true', () => {
        expect(subject.compareSignature(expectedSignature)).toBe(true);
      });
    });
  });

  describe('#verifySignature', () => {
    describe('when the signature is valid', () => {
      it('returns true', () => {
        expect(subject.verifySignature(key.publicKey)).toBe(true);
      });
    });

    describe('when there are no signatures', () => {
      const env: Envelope = { payload, payloadType, signatures: [] };
      const subject = new DSSESignatureContent(env);

      it('returns false', () => {
        expect(subject.verifySignature(key.publicKey)).toBe(false);
      });
    });

    describe('when the signature is NOT valid', () => {
      const invalidKey = crypto.generateKeyPairSync('ec', {
        namedCurve: 'secp256k1',
      });

      it('returns false', () => {
        expect(subject.verifySignature(invalidKey.publicKey)).toBe(false);
      });
    });
  });
});
