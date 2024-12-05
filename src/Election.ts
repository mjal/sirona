import sjcl from "sjcl";
import * as Trustee from "./Trustee";
import * as Point from "./Point";
import * as Question from "./Question";
import { genUUID } from "./utils"

export type t = {
  version: number;
  description: string;
  name: string;
  group: string;
  public_key: Point.t;
  questions: Question.t[];
  uuid: string;
  administrator?: string;
  credential_authority?: string;
  unrestricted?: boolean;
};

export type serialized_t = Omit<t, "public_key"> & { public_key: string };

export function parse(election: serialized_t): t {
  return {
    ...election,
    public_key: Point.parse(election.public_key),
  };
}

export function serialize(election: t): serialized_t {
  return {
    ...election,
    public_key: Point.serialize(election.public_key),
  };
}

export function create(
  description: string,
  name: string,
  trustees: Trustee.t[],
  questions: Question.t[]
) : t {
  const public_key = Trustee.combine_keys(trustees);

  const uuid = genUUID(14);

  return {
    version: 1,
    description,
    name,
    group: "Ed25519",
    public_key,
    questions,
    uuid
  };
}

export function verify(election: t, trustees: Array<Trustee.t>) {
  if (!Point.isValid(election.public_key)) {
    throw new Error("Invalid curve point");
  }

  if (!Point.isEqual(election.public_key, Trustee.combine_keys(trustees))) {
    throw new Error("Election Public Key doesn't correspond to trustees");
  }

  return true;
}

export function fingerprint(election: t): string {
  const str = JSON.stringify(serialize(election));

  return sjcl.codec.base64
    .fromBits(sjcl.hash.sha256.hash(str))
    .replace(/=+$/, "");
}
