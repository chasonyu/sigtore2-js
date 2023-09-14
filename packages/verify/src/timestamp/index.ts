import { VerificationError } from '../error';
import { verifyCheckpoint } from './checkpoint';
import { verifyMerkleInclusion } from './merkle';
import { verifyTLogSET } from './set';

import type {
  TLogEntryWithInclusionPromise,
  TLogEntryWithInclusionProof,
  TransparencyLogEntry,
} from '@sigstore/bundle';
import type {
  TLogAuthority,
  TimestampProvider,
  TimestampVerificationResult,
  TrustMaterial,
} from '../shared.types';

export function verifyTimestamps(
  provider: TimestampProvider,
  trustMaterial: TrustMaterial
): TimestampVerificationResult[] {
  return provider.timestamps().map((timestamp) => {
    switch (timestamp.$case) {
      case 'timestamp-authority':
        throw new VerificationError({
          code: 'NOT_IMPLEMENTED_ERROR',
          message: 'timestamp-authority not implemented',
        });
      case 'transparency-log':
        return verifyTLogTimestamp(timestamp.tlogEntry, trustMaterial.tlogs);
    }
  });
}

function verifyTLogTimestamp(
  entry: TransparencyLogEntry,
  tlogAuthorities: TLogAuthority[]
): TimestampVerificationResult {
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

  return {
    type: 'transparency-log',
    logID: entry.logId.keyId,
    timestamp: new Date(Number(entry.integratedTime) * 1000),
  };
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
