import { ed25519 } from '@noble/curves/ed25519';

export const g = ed25519.ExtendedPoint.BASE;
export const q = 2n ** 255n - 19n;
export const l = BigInt("0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");

