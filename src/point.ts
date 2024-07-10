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

export const g = ed25519.ExtendedPoint.BASE;
export const zero = ed25519.ExtendedPoint.ZERO;
