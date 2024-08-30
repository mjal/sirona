import sjcl from "sjcl";
import * as Z from "./Z";
import * as Point from "./Point";
import { range, b58chars } from "./utils"
import { g } from "./math";

export function derive(uuid: string, privcred: string) {
  const prefix = `derive_credential|${uuid}`;

  const x0 = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(`${prefix}|0|${privcred}`),
  );

  const x1 = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(`${prefix}|1|${privcred}`),
  );

  const nPrivateCredential = Z.modL(BigInt("0x" + x0 + x1));
  const pPublicCredential = g.multiply(nPrivateCredential);
  const hPublicCredential = Point.serialize(pPublicCredential);

  // TODO: Better names
  return {
    nPrivateCredential,
    hPublicCredential,
  };
}

export function generatePriv() {
  return range(25).map((i) => {
    if (i === 5 || i === 12 || i === 18) {
      return "-";
    }
    const randomIndex = Math.floor(Math.random() * b58chars.length);
    return b58chars[randomIndex];
  }).join("");
}
