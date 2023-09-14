import { CertAuthority } from './trust.types';

// const BEGINNING_OF_TIME = new Date(0);
// const END_OF_TIME = new Date(8640000000000000);

type FilterCriteria = {
  start: Date;
  end: Date;
};

// export function createCertAuthority(ca: CertificateAuthority): CertAuthority {
//   return {
//     certChain: ca.certChain.certificates.map((cert) =>
//       x509Certificate.parse(cert.rawBytes)
//     ),
//     validFor: {
//       start: ca.validFor.start || BEGINNING_OF_TIME,
//       end: ca.validFor.end || END_OF_TIME,
//     },
//   };
// }

export function filterCertAuthorities(
  certAuthorities: CertAuthority[],
  criteria: FilterCriteria
): CertAuthority[] {
  return certAuthorities.filter((ca) => {
    return (
      ca.validFor.start <= criteria.start && ca.validFor.end >= criteria.end
    );
  });
}
