import * as Point from "./point";

// -- Types

export type t = {
  pAlpha: Point.t;
  pBeta: Point.t;
};

export namespace Serialized {
  export type t = {
    alpha: string;
    beta: string;
  };
}

// -- Parse and serialize

export function parse(c: Serialized.t): t {
  return {
    pAlpha: Point.parse(c.alpha),
    pBeta: Point.parse(c.beta),
  };
}

export function serialize(c: t): Serialized.t {
  return {
    alpha: Point.serialize(c.pAlpha),
    beta: Point.serialize(c.pBeta),
  };
}

export const zero = { pAlpha: Point.zero, pBeta: Point.zero };

export function combine(a: t, b: t) {
  return {
    pAlpha: a.pAlpha.add(b.pAlpha),
    pBeta: a.pBeta.add(b.pBeta),
  };
}

export namespace Serialized {
  export function toString(ct: Serialized.t) {
    return `${ct.alpha},${ct.beta}`;
  }
}

export function toString(ct: t) {
  return Serialized.toString(serialize(ct));
}
