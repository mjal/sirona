import * as Ciphertext from "./Ciphertext";
import * as Proof from "./Proof";
import * as Z from "./Z";
import { ed25519 } from "@noble/curves/ed25519";
import type { ExtPointType as CurvePoint } from "@noble/curves/abstract/edwards.js";

export const g = ed25519.ExtendedPoint.BASE;
export const zero = ed25519.ExtendedPoint.ZERO;

export type t = CurvePoint;

export namespace Serialized {
  export type t = string;
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
  let a = Z.modQ(-1n);
  let d = Z.modQ(-(121665n * Z.modInverse(121666n, Z.q)));
  let curve = (p: t): bigint => {
    let x2 = p.ex * p.ex;
    let y2 = p.ey * p.ey;
    let z2 = p.ez * p.ez;
    let t2 = p.et * p.et;
    return Z.modQ(a * x2 + y2 - z2 - d * t2);
  };

  // WARN: In practice to have the same result as Belenios' we also
  // have to rule out the point serialized as all zeros
  if (
    isEqual(
      p,
      parse("0000000000000000000000000000000000000000000000000000000000000000"),
    )
  ) {
    return false;
  }

  return (
    p.ez > 0n &&
    Z.modQ(p.ex * p.ey) === Z.modQ(p.ez * p.et) &&
    curve(p) === 0n &&
    // WARN: Compared to Belenios, we cannot compute p ** L due to
    // limitations of the library. We will use the following workaround:
    // (p ** ( L - 1 )) * p
    isEqual(p.multiply(Z.L - 1n).add(p), zero)
  );
}

export function isValid(p: t): boolean {
  try {
    p.assertValidity();
  } catch (e) {
    if (isEqual(p, zero)) {
      return true;
    }
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
  res = res << padding;

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

// p1**e1 + p2**e2
export function compute_commitment(p1: t, p2: t, proof: Proof.t) {
  return p1.multiply(proof.nResponse).add(p2.multiply(proof.nChallenge));
}

//A = g**response * alpha**challenge
//B = y**response * (beta / (g**m))**challenge
export function compute_commitment_pair(
  y: t,
  eg: Ciphertext.t,
  proof: Proof.t,
  m: number,
) {
  const gPowerM = m === 0 ? zero : g.multiply(BigInt(m));
  const pBDivGPowerM = eg.pBeta.add(gPowerM.negate());

  const A = compute_commitment(g,  eg.pAlpha, proof);
  const B = compute_commitment(y, pBDivGPowerM, proof);

  return [A, B];
}

function reverseByteOrder(hexStr: string) {
  if (hexStr.length !== 64) {
    throw new Error("Serialized Point should be size 64");
  }
  return hexStr.match(/../g).reverse().join("");
}

