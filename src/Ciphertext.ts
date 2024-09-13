import * as Point from "./Point";

export type t = {
  pAlpha: Point.t;
  pBeta: Point.t;
};

export type serialized_t = {
  alpha: string;
  beta: string;
};

export function parse(c: serialized_t): t {
  return {
    pAlpha: Point.parse(c.alpha),
    pBeta: Point.parse(c.beta),
  };
}

export function serialize(c: t): serialized_t {
  return {
    alpha: Point.serialize(c.pAlpha),
    beta: Point.serialize(c.pBeta),
  };
}

export const zero = { pAlpha: Point.zero, pBeta: Point.zero };

export function combine(cts: Array<t>) {
  return cts.reduce((a, b) => {
    return {
      pAlpha: a.pAlpha.add(b.pAlpha),
      pBeta: a.pBeta.add(b.pBeta),
    };
  }, zero);
}

export namespace Serialized {
  export function toString(ct: serialized_t) {
    return `${ct.alpha},${ct.beta}`;
  }
}

export function toString(ct: t) {
  return Serialized.toString(serialize(ct));
}

export function isValid(ct: t) {
  return Point.isValid(ct.pAlpha) && Point.isValid(ct.pBeta);
}

export function encrypt(y: Point.t, nonce: bigint, plaintext: number) {
  const gPowerM =
    plaintext === 0 ? Point.zero : Point.g.multiply(BigInt(plaintext));
  const pAlpha = Point.g.multiply(nonce);
  const pBeta = y.multiply(nonce).add(gPowerM);
  return { pAlpha, pBeta };
}
