import sjcl from "sjcl";
import * as Point from "./Point";
import { g, L, mod } from "./math";

export function derive(uuid: string, privcred: string) {
  const prefix = `derive_credential|${uuid}`;

  const x0 = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(`${prefix}|0|${privcred}`),
  );

  const x1 = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(`${prefix}|1|${privcred}`),
  );

  const nPrivateCredential = mod(BigInt("0x" + x0 + x1), L);
  const pPublicCredential = g.multiply(nPrivateCredential);
  const hPublicCredential = Point.serialize(pPublicCredential);

  return {
    nPrivateCredential,
    hPublicCredential,
  };
}
