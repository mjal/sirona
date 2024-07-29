import * as Trustee from './Trustee'
import * as Point from './Point'
import * as Question from './Question'

export type t = {
  version: number,
  description: string,
  name: string,
  group: string,
  public_key: Point.Serialized.t,
  questions: Array<Question.t>,
  uuid: string,
  administrator?: string;
  credential_authority?: string;
}

export function verify(election: t, trustees: Array<Trustee.t>) {
  const pElectionPublicKey = Point.parse(election.public_key);
  if (!Point.isValid(pElectionPublicKey)) {
    throw new Error("Invalid curve point");
  }

  let pJointPublicKey = Point.zero;
  for (let i = 0; i < trustees.length; i++) {
    const trustee = trustees[i];
    if (trustee[0] === "Single") {
      const pX = Point.parse(trustee[1].public_key);
      pJointPublicKey = pJointPublicKey.add(pX);
    } else {
      // "Pedersen"
      const coefexps = trustee[1].coefexps.map((o) => {
        return JSON.parse(o.message).coefexps[0];
      });
      let sum = Point.zero;
      for (let j = 0; j < coefexps.length; j++) {
        sum = sum.add(Point.parse(coefexps[j]));
      }
      pJointPublicKey = pJointPublicKey.add(sum);
    }
  }

  if (
    Point.serialize(pJointPublicKey) !== election.public_key
  ) {
    throw new Error("Election Public Key doesn't correspond to trustees");
  }

  return true;
}
