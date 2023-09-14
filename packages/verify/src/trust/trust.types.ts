import type { KeyObject } from 'crypto';
import { x509Certificate } from '../x509/cert';

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
/* Move all this into client package */
/**
export type PublicKey = PublicKeyProto & {
  rawBytes: NonNullable<PublicKeyProto['rawBytes']>;
};

export type TransparencyLogInstance = TransparencyLogInstanceProto & {
  logId: NonNullable<TransparencyLogInstanceProto['logId']>;
  publicKey: PublicKey;
};

export type CertificateAuthority = CertificateAuthorityProto & {
  certChain: NonNullable<CertificateAuthorityProto['certChain']>;
  validFor: CertificateAuthorityProto['validFor'] & {
    start: NonNullable<CertificateAuthorityProto['validFor']>['start'];
  };
};

export type TrustedMaterial = {
  ctlogs: TransparencyLogInstance[];
  tlogs: TransparencyLogInstance[];
  certificateAuthorities: CertificateAuthority[];
  timestampAuthorities: CertificateAuthority[];
  publicKeys: { keyID: string; publicKey: PublicKey }[];
};
**/
