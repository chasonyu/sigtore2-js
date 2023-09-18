import type { KeyObject } from '../util/crypto';
import type { x509Certificate } from '../x509/cert';

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

export type TimeConstrainedKey = {
  publicKey: KeyObject;
  validFor(date: Date): boolean;
};

export type KeyFinderFunc = (hint: string) => TimeConstrainedKey;

export type TrustMaterial = {
  certificateAuthorities: CertAuthority[];
  timestampAuthorities: CertAuthority[];
  tlogs: TLogAuthority[];
  ctlogs: TLogAuthority[];
  publicKey: KeyFinderFunc;
};
