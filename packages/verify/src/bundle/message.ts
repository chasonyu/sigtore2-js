import { crypto } from '../util';

import type { MessageSignature } from '@sigstore/bundle';
import type { SignatureContent } from '../shared.types';

export class MessageSignatureContent implements SignatureContent {
  private readonly signature: Buffer;
  private readonly messageDigest: Buffer;
  private readonly artifact: Buffer;

  constructor(messageSignature: MessageSignature, artifact: Buffer) {
    this.signature = messageSignature.signature;
    this.messageDigest = messageSignature.messageDigest.digest;
    this.artifact = artifact;
  }

  public compareSignature(signature: Buffer): boolean {
    return crypto.bufferEqual(signature, this.signature);
  }

  public compareDigest(digest: Buffer): boolean {
    return crypto.bufferEqual(digest, this.messageDigest);
  }

  public verifySignature(key: crypto.KeyObject): boolean {
    return crypto.verify(this.artifact, key, this.signature);
  }
}
