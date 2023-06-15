import { ValidationError } from '../error';

import type { TransparencyLogInstance as TransparencyLogInstanceProto } from '@sigstore/protobuf-specs';
import type { TransparencyLogInstance } from './trust.types';

type FilterCriteria = {
  targetDate: Date;
  logID?: Buffer;
};

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

// Filter the list of tlog instances to only those which match the given log
// ID and have public keys which are valid for the given integrated time.
export function filterTLogInstances(
  tlogInstances: TransparencyLogInstance[],
  criteria: FilterCriteria
): TransparencyLogInstance[] {
  return tlogInstances.filter((tlog) => {
    const publicKey = tlog.publicKey;

    // If we're filtering by log ID the log IDs don't match, we can't use this
    // tlog
    if (criteria.logID && !tlog.logId.keyId.equals(criteria.logID)) {
      return false;
    }

    // If the tlog doesn't have a validFor field, we don't need to check it
    if (publicKey.validFor === undefined) {
      return true;
    }

    // Check that the integrated time is within the validFor range
    return (
      publicKey.validFor.start !== undefined &&
      publicKey.validFor.start <= criteria.targetDate &&
      (!publicKey.validFor.end || criteria.targetDate <= publicKey.validFor.end)
    );
  });
}
