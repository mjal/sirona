import { mod, modInverse, L, q, rev } from "./math";
import { ed25519 } from "@noble/curves/ed25519";
import type { ExtPointType } from "@noble/curves/abstract/edwards.js";

export type t = ExtPointType;

export namespace Serialized {
  export type t = string;
}

function reverseByteOrder(hexStr: string) {
  if (hexStr.length % 2 !== 0) {
    throw new Error("hex string should have an even number of characters");
  }
  return hexStr.match(/../g).reverse().join("");
}

export function serialize(p: t): Serialized.t {
  return reverseByteOrder(p.toHex());
}

export function parse(str: Serialized.t): t {
  return ed25519.ExtendedPoint.fromHex(reverseByteOrder(str));
}

export function combine(points: Array<t>): t {
  return points.reduce((acc, p) => acc.add(p), zero);
}

export function isEqual(a: t, b: t): boolean {
  return a.toHex() === b.toHex();
}

export function check(p: t): boolean {
  let a = mod(-1n, q);
  let d = mod(-(121665n * modInverse(121666n, q)), q);
  let curve = (p: t) : bigint => {
    let x2 = p.ex * p.ex;
    let y2 = p.ey * p.ey;
    let z2 = p.ez * p.ez;
    let t2 = p.et * p.et;
    return mod((a * x2) + y2 - z2 - (d * t2), q);
  }

  return p.ez !== 0n
    && mod(p.ex * p.ey, q) === mod(p.ez * p.et, q)
    && curve(p) === 0n
    && isEqual(p.multiply(L-1n).add(p), zero)
}

export function isValid(p: t): boolean {
  try {
    p.assertValidity();
  } catch (e) {
    return false;
  }
  if (!check(p)) {
    return false;
  }
  return true;
}

export function of_ints(xs: number[]) {
  const padding = 14n;
  const bits_per_int = 8n;
  const mask = 0xff;

  let res = 0n;
  for (let i = 0; i < xs.length; i++) {
    const x = xs[i] & mask;
    res = (res << bits_per_int) + BigInt(x);
  }
  res = (res << padding);


  let found = false;
  while (!found) {
    try {
      const point = parse(res.toString(16).padStart(64, "0"));
      if (isValid(point)) {
        return point;
      }
    } catch (e) {}
    res += 1n;
  }
}

export const g = ed25519.ExtendedPoint.BASE;
export const zero = ed25519.ExtendedPoint.ZERO;
