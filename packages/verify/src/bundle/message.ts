import type { MessageSignature } from '@sigstore/bundle';
import type { SignatureContent, SignatureVerifier } from '../shared.types';
import { crypto } from '../util';

export class MessageSignatureContent implements SignatureContent {
  private readonly messageSignature: MessageSignature;

  constructor(messageSignature: MessageSignature) {
    this.messageSignature = messageSignature;
  }

  public compareSignature(signature: Buffer): boolean {
    return crypto.bufferEqual(signature, this.signature);
  }

  public compareDigest(digest: Buffer): boolean {
    return crypto.bufferEqual(
      digest,
      this.messageSignature.messageDigest.digest
    );
  }

  public verifySignature(sigVerifier: SignatureVerifier): boolean {
    return sigVerifier.verifySignature(
      this.signature,
      this.messageSignature.messageDigest.digest
    );
  }

  private get signature(): Buffer {
    return this.messageSignature.signature;
  }
}
