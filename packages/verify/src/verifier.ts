import { isDeepStrictEqual } from 'util';
import { VerificationError } from './error';
import { verifyCertificate, verifyPublicKey } from './key';
import { verifyTLogTimestamp, verifyTSATimestamp } from './timestamp';
import { verifyTLogBody } from './tlog';
import { crypto } from './util';

import type { SignedEntity, Signer } from './shared.types';
import type { TrustMaterial } from './trust';

const OID_FULCIO_ISSUER = '1.3.6.1.4.1.57264.1.1';

export type VerifierOptions = {
  tlogThreshold?: number;
  ctlogThreshold?: number;
  tsaThreshold?: number;
};

type TimestampType = 'transparency-log' | 'timestamp-authority';

type TimestampVerificationResult = {
  type: TimestampType;
  logID: Buffer;
  timestamp: Date;
};

export class Verifier {
  private trustMaterial: TrustMaterial;
  private options: Required<VerifierOptions>;

  constructor(trustMaterial: TrustMaterial, options: VerifierOptions = {}) {
    this.trustMaterial = trustMaterial;
    this.options = {
      ctlogThreshold: options.ctlogThreshold ?? 1,
      tlogThreshold: options.tlogThreshold ?? 1,
      tsaThreshold: options.tsaThreshold ?? 0,
    };
  }

  public verify(entity: SignedEntity): void {
    const timestamps = this.verifyTimestamps(entity);

    const signer = this.verifySigningKey(entity, timestamps);

    this.verifyTLogs(entity);

    this.verifySignature(entity, signer);
  }

  private verifyTimestamps(entity: SignedEntity): Date[] {
    const timestamps = [];
    for (const timestamp of entity.timestamps) {
      switch (timestamp.$case) {
        /* istanbul ignore next */
        case 'timestamp-authority':
          if (this.options.tsaThreshold > 0) {
            verifyTSATimestamp(
              timestamp.timestamp,
              this.trustMaterial.timestampAuthorities
            );
            timestamps.push({
              type: 'timestamp-authority',
              logID: Buffer.from(''),
              timestamp: new Date(0),
            });
          }
          break;
        case 'transparency-log':
          if (this.options.tlogThreshold > 0) {
            const entry = timestamp.tlogEntry;
            verifyTLogTimestamp(timestamp.tlogEntry, this.trustMaterial.tlogs);
            timestamps.push({
              type: 'transparency-log',
              logID: entry.logId.keyId,
              timestamp: new Date(Number(entry.integratedTime) * 1000),
            });
          }
          break;
      }
    }
    // const timestamps = entity.timestamps.map<TimestampVerificationResult>(
    //   (timestamp) => {
    //     switch (timestamp.$case) {
    //       /* istanbul ignore next */
    //       case 'timestamp-authority':
    //         verifyTSATimestamp(
    //           timestamp.timestamp,
    //           this.trustMaterial.timestampAuthorities
    //         );
    //         return {
    //           type: 'timestamp-authority',
    //           logID: Buffer.from(''),
    //           timestamp: new Date(0),
    //         };
    //       case 'transparency-log':
    //         const entry = timestamp.tlogEntry;
    //         verifyTLogTimestamp(timestamp.tlogEntry, this.trustMaterial.tlogs);
    //         return {
    //           type: 'transparency-log',
    //           logID: entry.logId.keyId,
    //           timestamp: new Date(Number(entry.integratedTime) * 1000),
    //         };
    //     }
    //   }
    // );

    // Check for duplicate timestamps
    if (containsDupes(timestamps)) {
      throw new VerificationError({
        code: 'TIMESTAMP_ERROR',
        message: 'duplicate timestamp',
      });
    }

    return timestamps.map((t) => t.timestamp);
  }

  private verifySigningKey({ key }: SignedEntity, timestamps: Date[]): Signer {
    switch (key.$case) {
      case 'public-key': {
        const publicKey = verifyPublicKey(
          key.hint,
          timestamps,
          this.trustMaterial
        );

        return {
          issuer: undefined,
          subject: undefined,
          key: publicKey,
        };
      }
      case 'certificate': {
        const scts = verifyCertificate(
          key.certificate,
          timestamps,
          this.trustMaterial
        );

        /* istanbul ignore next - no fixture */
        if (containsDupes(scts)) {
          throw new VerificationError({
            code: 'CERTIFICATE_ERROR',
            message: 'duplicate SCT',
          });
        }

        return {
          issuer: key.certificate
            .extension(OID_FULCIO_ISSUER)
            ?.value.toString('ascii'),
          subject: undefined,
          key: crypto.createPublicKey(key.certificate.publicKey),
        };
      }
    }
  }

  private verifyTLogs({ signature: content, tlogEntries }: SignedEntity): void {
    tlogEntries.forEach((entry) => verifyTLogBody(entry, content));
  }

  private verifySignature(entity: SignedEntity, signer: Signer): void {
    if (!entity.signature.verifySignature(signer.key)) {
      throw new VerificationError({
        code: 'SIGNATURE_ERROR',
        message: 'signature verification failed',
      });
    }
  }
}

// Checks for duplicate items in the array. Objects are compared using
// deep equality.
function containsDupes(arr: unknown[]): boolean {
  for (let i = 0; i < arr.length; i++) {
    for (let j = i + 1; j < arr.length; j++) {
      if (isDeepStrictEqual(arr[i], arr[j])) {
        return true;
      }
    }
  }

  return false;
}
