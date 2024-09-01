import sjcl from "sjcl";
import * as Zq from "./Zq";
import * as Point from "./Point";
import { range, b58chars } from "./utils";

export function derive(uuid: string, privcred: string) {
  const prefix = `derive_credential|${uuid}`;

  const x0 = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(`${prefix}|0|${privcred}`),
  );

  const x1 = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(`${prefix}|1|${privcred}`),
  );

  const nPrivateCredential = Zq.mod(BigInt("0x" + x0 + x1));
  const pPublicCredential = Point.g.multiply(nPrivateCredential);
  const hPublicCredential = Point.serialize(pPublicCredential);

  // TODO: Better names
  return {
    nPrivateCredential,
    hPublicCredential,
  };
}

export function generatePriv() {
  return range(25)
    .map((i) => {
      if (i === 5 || i === 12 || i === 18) {
        return "-";
      }
      const randomIndex = Math.floor(Math.random() * b58chars.length);
      return b58chars[randomIndex];
    })
    .join("");
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
