import * as Point from "./Point";

export type t = {
  alpha: Point.t;
  beta: Point.t;
};

export type serialized_t = {
  alpha: string;
  beta: string;
};

export function parse(c: serialized_t): t {
  return {
    alpha: Point.parse(c.alpha),
    beta: Point.parse(c.beta),
  };
}

export function serialize(c: t): serialized_t {
  return {
    alpha: Point.serialize(c.alpha),
    beta: Point.serialize(c.beta),
  };
}

export const zero = { alpha: Point.zero, beta: Point.zero };

export function combine(cts: Array<t>) {
  return cts.reduce((a: t, b: t) => {
    return {
      alpha: a.alpha.add(b.alpha),
      beta: a.beta.add(b.beta),
    };
  }, zero);
}

export function toStringS(ct: serialized_t) {
  return `${ct.alpha},${ct.beta}`;
}

export function toString(ct: t) {
  return toStringS(serialize(ct));
}

export function isValid(ct: t) {
  return Point.isValid(ct.alpha) && Point.isValid(ct.beta);
}

export function encrypt(y: Point.t, nonce: bigint, plaintext: number) {
  const gPowerM =
    plaintext === 0 ? Point.zero : Point.g.multiply(BigInt(plaintext));
  const alpha = Point.g.multiply(nonce);
  const beta = y.multiply(nonce).add(gPowerM);
  return { alpha, beta };
}
