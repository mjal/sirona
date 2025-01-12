import sjcl from "sjcl";
import * as Zq from "./Zq";
import * as Point from "./Point";
import { genUUID } from "./utils";

export function derive(uuid: string, privcred: string) {
  const prefix = `derive_credential|${uuid}`;

  const x0 = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(`${prefix}|0|${privcred}`),
  );

  const x1 = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(`${prefix}|1|${privcred}`),
  );

  const priv = Zq.mod(BigInt("0x" + x0 + x1));
  const pub = Point.serialize(Point.g.multiply(priv));

  return { pub, priv }
}

export function generatePriv() {
  return [genUUID(5), genUUID(6), genUUID(5), genUUID(6)].join("-");
}

export function find(credentials: string[], credential: string) {
  return (
    credentials
      .map((line: string) => line.split(",")[0])
      .indexOf(credential) !== -1
  );
}

export function checkSeedFormat(credential: string) {
  return /[a-zA-Z0-9]{5}-[a-zA-Z0-9]{6}-[a-zA-Z0-9]{5}-[a-zA-Z0-9]{6}/.test(
    credential,
  );
}
