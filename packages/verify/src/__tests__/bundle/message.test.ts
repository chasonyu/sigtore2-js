import { HashAlgorithm } from '@sigstore/protobuf-specs';
import crypto from 'crypto';
import { MessageSignatureContent } from '../../bundle/message';
import { hash } from '../../util/crypto';

import type { MessageSignature } from '@sigstore/bundle';

describe('MessageSignatureContent', () => {
  const key = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
  const message = Buffer.from('message');
  const messageDigest = hash(message);

  const messageSignature: MessageSignature = {
    messageDigest: { digest: messageDigest, algorithm: HashAlgorithm.SHA2_256 },
    signature: crypto.sign(null, message, key.privateKey),
  };

  const subject = new MessageSignatureContent(messageSignature, message);

  describe('#compareDigest', () => {
    describe('when the digest does NOT match the message hash', () => {
      it('returns false', () => {
        expect(subject.compareDigest(Buffer.from(''))).toBe(false);
      });
    });

    describe('when the digest matches the message hash', () => {
      it('returns true', () => {
        expect(subject.compareDigest(messageDigest)).toBe(true);
      });
    });
  });

  describe('#compareSignature', () => {
    describe('when the signature does NOT match the message signature', () => {
      it('returns false', () => {
        expect(subject.compareSignature(Buffer.from(''))).toBe(false);
      });
    });

    describe('when the signature matches the message signature', () => {
      it('returns true', () => {
        expect(subject.compareSignature(messageSignature.signature)).toBe(true);
      });
    });
  });

  describe('#verifySignature', () => {
    describe('when the signature is NOT valid', () => {
      const invalidKey = crypto.generateKeyPairSync('ec', {
        namedCurve: 'secp256k1',
      });

      it('returns false', () => {
        expect(subject.verifySignature(invalidKey.publicKey)).toBe(false);
      });
    });

    describe('when the signature is valid', () => {
      it('returns true', () => {
        expect(subject.verifySignature(key.publicKey)).toBe(true);
      });
    });
  });
});
