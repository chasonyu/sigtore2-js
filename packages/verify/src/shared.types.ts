import type { TransparencyLogEntry } from '@sigstore/bundle';
import type { KeyObject } from 'crypto';
import type { x509Certificate } from './x509/cert';

export interface SCTVerificationResult {
  logID: Buffer;
}

export type Signer = {
  key: KeyObject;
  issuer: string | undefined;
  subject: string | undefined;
};

// TODO: Implement this!
export type RFC3161Timestamp = object;

export type Timestamp =
  | {
      $case: 'timestamp-authority';
      timestamp: RFC3161Timestamp;
    }
  | {
      $case: 'transparency-log';
      tlogEntry: TransparencyLogEntry;
    };

export type VerificationKey =
  | {
      $case: 'public-key';
      hint: string;
    }
  | {
      $case: 'certificate';
      certificate: x509Certificate;
    };

export type SignatureContent = {
  compareSignature(signature: Buffer): boolean;
  compareDigest(digest: Buffer): boolean;
  verifySignature(key: KeyObject): boolean;
};

export type TimestampProvider = {
  timestamps: Timestamp[];
};

export type SignatureProvider = {
  signature: SignatureContent;
};

export type KeyProvider = {
  key: VerificationKey;
};

export type TLogEntryProvider = {
  tlogEntries: TransparencyLogEntry[];
};

export type SignedEntity = SignatureProvider &
  KeyProvider &
  TimestampProvider &
  TLogEntryProvider;
