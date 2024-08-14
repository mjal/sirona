import * as Point from "./Point";
import * as Proof from "./Proof";
import * as Election from "./Election";
import { Hpok } from "./math";

export type t = single | pedersen;

export type single = ["Single", public_key_with_pok];

export type pedersen = [
  "Pedersen",
  {
    threshold: number;
    certs: Array<signed_message>;
    coefexps: Array<signed_message>;
    verification_keys: Array<public_key_with_pok>;
  },
];

export type public_key_with_pok = {
  pok: Proof.Serialized.t;
  public_key: Point.Serialized.t;
};

export type signed_message = {
  message: string;
  signature: Proof.Serialized.t;
};

export function verify(election: Election.t, trustee: t) {
  if (trustee[0] === "Single") {
    if (!checkPublicKey(election, trustee[1])) {
      return false;
    }
  } else {
    // "Pedersen"
    for (let j = 0; j < trustee[1].verification_keys.length; j++) {
      if (checkPublicKey(election, trustee[1].verification_keys[j])) {
        return false;
      }
    }
  }
  return true;
}

function checkPublicKey(election: Election.t, trustee: public_key_with_pok) {
  const pX = Point.parse(trustee.public_key);

  if (!Point.isValid(pX)) {
    throw new Error("Invalid curve point");
  }

  const nChallenge = BigInt(trustee.pok.challenge);
  const nResponse = BigInt(trustee.pok.response);

  const pA = Point.g.multiply(nResponse).add(pX.multiply(nChallenge));

  const S = `${election.group}|${trustee.public_key}`;

  if (Hpok(S, pA) !== nChallenge) {
    throw new Error("Trustee POK is invalid");
  }
  return true;
}
