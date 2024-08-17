import * as Event from "./Event";
import * as Point from "./Point";
import * as Trustee from "./Trustee";
import * as Election from "./Election";

type t = {
  trustees: Trustee.t[];
  election: Election.t;
  credentials: Array<string>;
};

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
