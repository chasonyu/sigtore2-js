import type { CertAuthority, TLogAuthority } from './trust.types';

type CertAuthorityFilterCriteria = {
  start: Date;
  end: Date;
};

export function filterCertAuthorities(
  certAuthorities: CertAuthority[],
  criteria: CertAuthorityFilterCriteria
): CertAuthority[] {
  return certAuthorities.filter((ca) => {
    return (
      ca.validFor.start <= criteria.start && ca.validFor.end >= criteria.end
    );
  });
}

type TLogAuthorityFilterCriteria = {
  targetDate: Date;
  logID?: Buffer;
};

// Filter the list of tlog instances to only those which match the given log
// ID and have public keys which are valid for the given integrated time.
export function filterTLogAuthorities(
  tlogAuthorities: TLogAuthority[],
  criteria: TLogAuthorityFilterCriteria
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
