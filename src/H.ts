import * as Point from "./Point";
import * as Z from "./Z";
import sjcl from "sjcl";

export default function(prefix: string, ...commitments: Array<Point.t>) {
  const str = `${prefix}|${commitments.map(Point.serialize).join(",")}`;
  const h = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(str));
  return Z.modL(BigInt("0x" + h));
}
