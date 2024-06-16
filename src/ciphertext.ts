import { rev, parsePoint } from "./math";
import * as Point from './point';

export type t = {
  pAlpha: Point.t;
  pBeta: Point.t
};

export namespace Serialized {
  export type t = {
    alpha: string;
    beta: string
  }
};

export function serialize(c: t): Serialized.t {
  return {
    alpha: Point.serialize(c.pAlpha),
    beta:  Point.serialize(c.pBeta),
  };
}

export function parse(c: Serialized.t): t {
  return {
    pAlpha: Point.parse(c.alpha),
    pBeta: Point.parse(c.beta),
  };
}

