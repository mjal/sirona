import * as Point from "./Point";
import * as Z from "./Z";
import sjcl from "sjcl";

function H(prefix: string, ...commitments: Array<Point.t>) {
  const str = `${prefix}|${commitments.map(Point.serialize).join(",")}`;
  const h = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(str));
  return Z.modL(BigInt("0x" + h));
}

export function Hiprove(
  S: string,
  alpha: Point.t,
  beta: Point.t,
  ...commitments: Array<Point.t>
) {
  const prefix = `prove|${S}|${Point.serialize(alpha)},${Point.serialize(beta)}`;
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
