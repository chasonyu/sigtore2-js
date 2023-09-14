import { SignedEntity } from './shared.types';
import { verifyTimestamps } from './timestamp';
import { TrustMaterial } from './trust';

export class Verifier {
  private trustMaterial: TrustMaterial;

  constructor(trustMaterial: TrustMaterial) {
    this.trustMaterial = trustMaterial;
  }

  public verify(entity: SignedEntity): void {
    const timestamps = verifyTimestamps(
      entity,
      this.trustMaterial
    );

    timestamps.forEach((timestamp) => {
  }
}
