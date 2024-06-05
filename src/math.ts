import { sjcl } from "sjcl";
import { ed25519 } from "@noble/curves/ed25519";
import type { ExtPointType } from "@noble/curves/abstract/edwards.js";

export const g = ed25519.ExtendedPoint.BASE;
export const zero = ed25519.ExtendedPoint.ZERO;
//export const one = ed25519.ExtendedPoint.fromHex(
//  "0100000000000000000000000000000000000000000000000000000000000000",
//);

export const q = 2n ** 255n - 19n;
export const L = BigInt(
  "0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
);

export const rev = (hexStr: string): string => {
  const match = hexStr.match(/.{1,2}/g);
  if (match !== null) {
    return match.reverse().join("");
  } else {
    return "";
  }
};

export const mod = (a: bigint, b: bigint) => {
  let remainder = a % b;
  if (remainder < 0) {
    remainder += b;
  }
  return remainder;
};

export const isValidPoint = (point: ExtPointType) => {
  try {
    point.assertValidity();
  } catch (e) {
    return false;
  }
  return true;
};

export const parsePoint = (str: string) => {
  return ed25519.ExtendedPoint.fromHex(rev(str));
};

function egcd(a: bigint, b: bigint): [bigint, bigint, bigint] {
  if (b === 0n) {
    return [a, 1n, 0n];
  }
  const [g, x1, y1] = egcd(b, a % b);
  return [g, y1, x1 - (a / b) * y1];
}

export function modInverse(a: bigint, m: bigint): bigint {
  const [g, x, _] = egcd(a, m);
  if (g !== 1n) {
    throw new Error(`${a} n'a pas d'inverse modulaire sous ${m}`);
  }
  return ((x % m) + m) % m;
}

export function random() : bigint {
  const bitArray = sjcl.random.randomWords(8);
  const hNumber = sjcl.codec.hex.fromBits(bitArray);
  return BigInt("0x" + hNumber);
}
