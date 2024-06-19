import * as Point from "./point";

import sjcl from "sjcl";
import { ed25519 } from "@noble/curves/ed25519";

export const zero = ed25519.ExtendedPoint.ZERO;
export const g = ed25519.ExtendedPoint.BASE;
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

// TODO: Move to point.ts
export const isValidPoint = (point: Point.t) => {
  try {
    point.assertValidity();
  } catch (e) {
    return false;
  }
  return true;
};

// TODO: Remove
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

export function rand(): bigint {
  const bitArray = sjcl.random.randomWords(8);
  const hNumber = sjcl.codec.hex.fromBits(bitArray);
  return mod(BigInt("0x" + hNumber), L);
}

export function formula(p1: Point.t, e1: bigint, p2: Point.t, e2: bigint) {
  return p1.multiply(e1).add(p2.multiply(e2));
}

//A = g**response * alpha**challenge
//B = y**response * (beta / (g**m))**challenge
export function formula2(
  pY: Point.t,
  pAlpha: Point.t,
  pBeta: Point.t,
  nChallenge: bigint,
  nResponse: bigint,
  m: number,
) {
  const pA = formula(g, nResponse, pAlpha, nChallenge);
  const gPowerM = m === 0 ? zero : g.multiply(BigInt(m));
  const pBDivGPowerM = pBeta.add(gPowerM.negate());
  const pB = formula(pY, nResponse, pBDivGPowerM, nChallenge);

  return [pA, pB];
}

function H(prefix: string, ...commitments: Array<Point.t>) {
  const str = `${prefix}|${commitments.map((p) => rev(p.toHex())).join(",")}`;
  const h = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(str));
  return mod(BigInt("0x" + h), L);
}

export function Hiprove(
  S: string,
  alpha: Point.t,
  beta: Point.t,
  ...commitments: Array<Point.t>
) {
  const prefix = `prove|${S}|${rev(alpha.toHex())},${rev(beta.toHex())}`;
  return H(prefix, ...commitments);
}

export function Hbproof0(S: string, ...commitments: Array<Point.t>) {
  return H(`bproof0|${S}`, ...commitments);
}

export function Hbproof1(S: string, ...commitments: Array<Point.t>) {
  return H(`bproof1|${S}`, ...commitments);
}

export function Hsignature(S: string, A: Point.t) {
  return H(`sig|${S}`, A);
}

export function Hpok(S: string, A: Point.t) {
  return H(`pok|${S}`, A);
}

export function Hnonzero(S: string, ...commitments: Array<Point.t>) {
  return H(`nonzero|${S}`, ...commitments);
}
