import * as Point from "./Point";
import * as Trustee from "./Trustee";
import * as Election from "./Election";

export type t = {
  trustees: Trustee.t[];
  election: Election.t;
  credentials: string[];
};

export type serialized_t = {
  trustees: Trustee.serialized_t[];
  election: Election.serialized_t;
  credentials: string[];
};

export function serialize(setup: t): serialized_t {
  let trustees = setup.trustees.map(Trustee.serialize)
  let election = Election.serialize(setup.election)
  let credentials = setup.credentials
  return {
    election,
    trustees,
    credentials
  };
}

export function parse(setup: serialized_t): t {
  let trustees = setup.trustees.map(Trustee.parse)
  let election = Election.parse(setup.election)
  let credentials = setup.credentials
  return {
    election,
    trustees,
    credentials
  };
}

export function verify(setup: t) {
  let { trustees, election, credentials } = setup;

  for (let i = 0; i < trustees.length; i++) {
    if (Trustee.verify(election, trustees[i]) === false) {
      return false;
    }
  }

  for (let i = 0; i < credentials.length; i++) {
    let publicKey = credentials[i].split(",")[0];
    if (Point.isValid(Point.parse(publicKey)) === false) {
      return false;
    }
  }

  if (Election.verify(election, trustees) === false) {
    return false;
  }

  return true;
}
