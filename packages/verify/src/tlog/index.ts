import { VerificationError } from '../error';
import { verifyTLogBody } from './body';
import { verifyCheckpoint } from './checkpoint';
import { verifyMerkleInclusion } from './merkle';
import { verifyTLogSET } from './set';

import type {
  TLogEntryWithInclusionPromise,
  TLogEntryWithInclusionProof,
  TransparencyLogEntry,
} from '@sigstore/bundle';
import type {
  SignatureContent,
  SignatureProvider,
  TLogEntryProvider,
  TimestampVerificationResult,
} from '../shared.types';
import type { TLogAuthority } from '../trust';

type TLogVerifiable = SignatureProvider & TLogEntryProvider;

export type TransparencyLogVerifierOptions = {
  tlogAuthorities: TLogAuthority[];
  online: boolean;
};

export class TransparencyLogVerifier {
  private tlogAuthorities: TLogAuthority[];
  private online: boolean;

  constructor(options: TransparencyLogVerifierOptions) {
    this.tlogAuthorities = options.tlogAuthorities;
    this.online = options.online;
  }

  verify(entity: TLogVerifiable): TimestampVerificationResult[] {
    const content = entity.signature();

    if (this.online) {
      throw new VerificationError({
        code: 'NOT_IMPLEMENTED_ERROR',
        message: 'online verification is not implemented',
      });
    }

    return entity
      .tlogEntries()
      .map((entry) => this.verifyTLogEntry(entry, content));
  }

  private verifyTLogEntry(
    entry: TransparencyLogEntry,
    content: SignatureContent
  ): TimestampVerificationResult {
    let inclusionVerified = false;

    if (isTLogEntryWithInclusionPromise(entry)) {
      verifyTLogSET(entry, this.tlogAuthorities);
      inclusionVerified = true;
    }

    if (isTLogEntryWithInclusionProof(entry)) {
      verifyMerkleInclusion(entry);
      verifyCheckpoint(entry, this.tlogAuthorities);
      inclusionVerified = true;
    }

    if (!inclusionVerified) {
      throw new VerificationError({
        code: 'TLOG_MISSING_INCLUSION_ERROR',
        message: 'inclusion could not be verified',
      });
    }

    verifyTLogBody(entry, content);

    return {
      type: 'transparency-log',
      logID: entry.logId.keyId,
      timestamp: new Date(Number(entry.integratedTime) * 1000),
    };
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
