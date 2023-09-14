import type { TransparencyLogEntry } from '@sigstore/bundle';
import type { KeyObject } from './util/crypto';
import { x509Certificate } from './x509/cert';

export type SignatureVerifier = {
  verifySignature(signature: Buffer, data: Buffer): boolean;
  scts: SCTVerificationResult[];
  issuer: string | undefined;
  subject: string | undefined;
};

type ValidityPeriodChecker = {
  validFor(date: Date): boolean;
};

export type TimeConstrainedKey = ValidityPeriodChecker & {
  publicKey: KeyObject;
};

/******************************************************************************/
// Trust Material
/******************************************************************************/

export type TLogAuthority = {
  logID: Buffer;
  publicKey: KeyObject;
  validFor: {
    start: Date;
    end: Date;
  };
};

export type CertAuthority = {
  certChain: x509Certificate[];
  validFor: {
    start: Date;
    end: Date;
  };
};

export type TrustMaterial = {
  certificateAuthorities: CertAuthority[];
  timestampAuthorities: CertAuthority[];
  tlogs: TLogAuthority[];
  ctlogs: TLogAuthority[];
  publicKey(keyID: string): TimeConstrainedKey;
};

/******************************************************************************/
// Signed Entity
/******************************************************************************/

// TODO: Implement this!
type RFC3161Timestamp = {};

export type Timestamp =
  | {
      $case: 'timestamp-authority';
      timestamp: RFC3161Timestamp;
    }
  | {
      $case: 'transparency-log';
      tlogEntry: TransparencyLogEntry;
    };

export type SignatureContent = {
  compareSignature(signature: Buffer): boolean;
  compareDigest(digest: Buffer): boolean;
  verifySignature(sigVerifier: SignatureVerifier): boolean;
};

export type TimestampProvider = {
  timestamps(): Timestamp[];
};

export type SignatureProvider = {
  signature(): SignatureContent;
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

export type KeyProvider = {
  key(): VerificationKey;
};

export type TLogEntryProvider = {
  tlogEntries(): TransparencyLogEntry[];
};

export type SignedEntity = SignatureProvider &
  KeyProvider &
  TimestampProvider &
  TLogEntryProvider;

/******************************************************************************/
// Signed Entity
/******************************************************************************/

export type TimestampType = 'transparency-log' | 'timestamp-authority';

export type TimestampVerificationResult = {
  type: TimestampType;
  logID: Buffer;
  timestamp: Date;
};

export interface SCTVerificationResult {
  logID: Buffer;
}
