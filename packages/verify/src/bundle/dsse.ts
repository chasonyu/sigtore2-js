import type { Envelope } from '@sigstore/bundle';
import type { SignatureContent, SignatureVerifier } from '../shared.types';
import { crypto } from '../util';

const PAE_PREFIX = 'DSSEv1';

export class DSSESignatureContent implements SignatureContent {
  private readonly env: Envelope;

  constructor(env: Envelope) {
    this.env = env;
    const x = this.env.signatures[0];
  }

  public compareDigest(digest: Buffer): boolean {
    return crypto.bufferEqual(digest, crypto.hash(this.env.payload));
  }

  public compareSignature(signature: Buffer): boolean {
    return crypto.bufferEqual(signature, this.signature);
  }

  public verifySignature(sigVerifier: SignatureVerifier): boolean {
    return sigVerifier.verifySignature(this.signature, this.preAuthEncoding);
  }

  private get signature(): Buffer {
    return this.env.signatures.length > 0
      ? this.env.signatures[0].sig
      : Buffer.from('');
  }

  // DSSE Pre-Authentication Encoding
  private get preAuthEncoding(): Buffer {
    const prefix = [
      PAE_PREFIX,
      this.env.payloadType.length,
      this.env.payloadType,
      this.env.payload.length,
      '',
    ].join(' ');

    return Buffer.concat([Buffer.from(prefix, 'ascii'), this.env.payload]);
  }
}
