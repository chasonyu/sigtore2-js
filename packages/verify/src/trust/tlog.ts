// import type { TransparencyLogInstance } from './trust.types';
import { TLogAuthority } from './trust.types';

const BEGINNING_OF_TIME = new Date(0);
const END_OF_TIME = new Date(8640000000000000);

type FilterCriteria = {
  targetDate: Date;
  logID?: Buffer;
};

/**
function createTLogAuthority(
  tlogInstance: TransparencyLogInstance
): TLogAuthority {
  return {
    logID: tlogInstance.logId.keyId,
    publicKey: createPublicKey(tlogInstance.publicKey.rawBytes),
    validFor: {
      start: tlogInstance.publicKey.validFor?.start || BEGINNING_OF_TIME,
      end: tlogInstance.publicKey.validFor?.end || END_OF_TIME,
    },
  };
}

export function assertTransparencyLogInstance(
  tlogInstance: TransparencyLogInstanceProto
): asserts tlogInstance is TransparencyLogInstance {
  const invalidValues: string[] = [];

  if (!tlogInstance.logId) {
    invalidValues.push('logId');
  }

  if (!tlogInstance.publicKey) {
    invalidValues.push('publicKey');
  } else {
    if (!tlogInstance.publicKey.rawBytes) {
      invalidValues.push('publicKey.rawBytes');
    }
  }

  if (invalidValues.length > 0) {
    throw new ValidationError(
      'invalid transparency log instance',
      invalidValues
    );
  }
}
**/

// Filter the list of tlog instances to only those which match the given log
// ID and have public keys which are valid for the given integrated time.
export function filterTLogAuthorities(
  tlogAuthorities: TLogAuthority[],
  criteria: FilterCriteria
): TLogAuthority[] {
  return tlogAuthorities.filter((tlog) => {
    // If we're filtering by log ID and the log IDs don't match, we can't use
    // this tlog
    if (criteria.logID && !tlog.logID.equals(criteria.logID)) {
      return false;
    }

    // Check that the integrated time is within the validFor range
    return (
      tlog.validFor.start <= criteria.targetDate &&
      criteria.targetDate <= tlog.validFor.end
    );
  });
}
