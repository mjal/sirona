import sjcl from "sjcl";
import * as Trustee from "./Trustee";
import * as Point from "./Point";
import * as Question from "./Question";

export type t = {
  version: number;
  description: string;
  name: string;
  group: string;
  public_key: Point.Serialized.t;
  questions: Array<Question.t>;
  uuid: string;
  administrator?: string;
  credential_authority?: string;
};

export function verify(election: t, trustees: Array<Trustee.t>) {
  const publicKey = Point.parse(election.public_key);

  if (!Point.isValid(publicKey)) {
    throw new Error("Invalid curve point");
  }

  if (!Point.isEqual(publicKey, Trustee.combine_keys(trustees))) {
    throw new Error("Election Public Key doesn't correspond to trustees");
  }

  return true;
}

export function fingerprint(election: t): string {
  return sjcl.codec.base64
    .fromBits(sjcl.hash.sha256.hash(JSON.stringify(election)))
    .replace(/=+$/, "");
}
