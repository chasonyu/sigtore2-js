import type {
  CertificateAuthority,
  PublicKey as PublicKeyProto,
  TransparencyLogInstance as TransparencyLogInstanceProto,
} from '@sigstore/protobuf-specs';

export type PublicKey = PublicKeyProto & {
  rawBytes: NonNullable<PublicKeyProto['rawBytes']>;
};

export type TransparencyLogInstance = TransparencyLogInstanceProto & {
  logId: NonNullable<TransparencyLogInstanceProto['logId']>;
  publicKey: PublicKey;
};

type TrustedMaterial = {
  ctlogs: TransparencyLogInstance[];
  tlogs: TransparencyLogInstance[];
  certificateAuthorities: CertificateAuthority[];
  timestampAuthorities: CertificateAuthority[];
  publicKeys: { keyID: string; publicKey: PublicKey }[];
};
