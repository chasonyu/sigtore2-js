import assert from 'assert';
import { VerificationError } from '../error';
import { verifyCheckpoint } from './checkpoint';
import { verifyMerkleInclusion } from './merkle';
import { verifyTLogSET } from './set';

import type {
  TLogEntryWithInclusionPromise,
  TLogEntryWithInclusionProof,
  TransparencyLogEntry,
} from '@sigstore/bundle';
import type { RFC3161Timestamp } from '../shared.types';
import type { CertAuthority, TLogAuthority } from '../trust';

/* istanbul ignore next */
export function verifyTSATimestamp(
  timestamp: RFC3161Timestamp,
  timestampAuthorities: CertAuthority[]
): void {
  assert(timestamp);
  assert(timestampAuthorities);
  throw new VerificationError({
    code: 'NOT_IMPLEMENTED_ERROR',
    message: 'timestamp-authority not implemented',
  });
}

export function verifyTLogTimestamp(
  entry: TransparencyLogEntry,
  tlogAuthorities: TLogAuthority[]
): void {
  let inclusionVerified = false;

  if (isTLogEntryWithInclusionPromise(entry)) {
    verifyTLogSET(entry, tlogAuthorities);
    inclusionVerified = true;
  }

  if (isTLogEntryWithInclusionProof(entry)) {
    verifyMerkleInclusion(entry);
    verifyCheckpoint(entry, tlogAuthorities);
    inclusionVerified = true;
  }

  if (!inclusionVerified) {
    throw new VerificationError({
      code: 'TLOG_MISSING_INCLUSION_ERROR',
      message: 'inclusion could not be verified',
    });
  }
}

function isTLogEntryWithInclusionPromise(
  entry: TransparencyLogEntry
): entry is TLogEntryWithInclusionPromise {
  return entry.inclusionPromise !== undefined;
}

function isTLogEntryWithInclusionProof(
  entry: TransparencyLogEntry
): entry is TLogEntryWithInclusionProof {
  return entry.inclusionProof !== undefined;
}
