import type { Envelope, TransparencyLogEntry } from '@sigstore/bundle';
import type { KeyObject } from './util/crypto';
export type SignatureProvider = {
  signature(): SignatureContent;
};

export type KeyIDProvider = {
  keyID(): string;
};

export type CertificateProvider = {
  certificateChain(): Buffer[];
};

export type EnvelopeProvider = {
  envelope(): Envelope;
};

export type SignedTimestampProvider = {
  timestamps(): Buffer[];
};

export type TLogEntryProvider = {
  tlogEntries(): TransparencyLogEntry[];
};

export type SignedEntity = SignatureProvider &
  KeyIDProvider &
  CertificateProvider &
  EnvelopeProvider &
  SignedTimestampProvider &
  TLogEntryProvider;

export type Policy = {
  verify(entity: SignedEntity): Promise<void>;
};

export type SignatureVerifier = {
  publicKey: KeyObject;
  verifySignature(signature: Buffer, data: Buffer): boolean;
};

export type SignatureContent = {
  compareSignature(signature: Buffer): boolean;
  compareDigest(digest: Buffer): boolean;
  verifySignature(sigVerifier: SignatureVerifier): boolean;
};

type TimestampType = 'transparency-log' | 'timestamp-authority';
export type TimestampVerificationResult = {
  type: TimestampType;
  logID: Buffer;
  timestamp: Date;
};
