import sjcl from "sjcl";

export const q = 2n ** 255n - 19n;

export const mod = (a: bigint, b: bigint) => {
  let r = a % b;
  return (r >= 0) ? r : r + b;
};

export function rand(max: bigint): bigint {
  const bitArray = sjcl.random.randomWords(8);
  const hNumber = sjcl.codec.hex.fromBits(bitArray);
  return mod(BigInt("0x" + hNumber), max);
}

export function modInverse(a: bigint, m: bigint): bigint {
  const [g, x, _] = egcd(a, m);
  if (g !== 1n) {
    throw new Error(`${a} n'a pas d'inverse modulaire sous ${m}`);
  }
  return ((x % m) + m) % m;
}

function egcd(a: bigint, b: bigint): [bigint, bigint, bigint] {
  if (b === 0n) {
    return [a, 1n, 0n];
  }
  const [g, x1, y1] = egcd(b, a % b);
  return [g, y1, x1 - (a / b) * y1];
}

import * as Point from "./Point";
import H from "./H";

export function Hpok(S: string, A: Point.t) {
  return H(`pok|${S}`, A);
}

export function Hnonzero(S: string, ...commitments: Array<Point.t>) {
  return H(`nonzero|${S}`, ...commitments);
}

export function Hlproof(S: string, ...commitments: Array<Point.t>) {
  return H(`lproof|${S}`, ...commitments);
}

export function Hdecrypt(S: string, ...commitments: Array<Point.t>) {
  return H(`decrypt|${S}`, ...commitments);
}

export function Hraweg(
  S: string,
  y: Point.t,
  alpha: Point.t,
  beta: Point.t,
  A: Point.t,
) {
  let prefix = `raweg|${S}|`;
  prefix += Point.serialize(y) + ",";
  prefix += Point.serialize(alpha) + ",";
  prefix += Point.serialize(beta);
  return H(prefix, A);
}
