import sjcl from "sjcl";
import * as Credential from "./Credential";
import * as Proof from "./Proof";
import * as SchnorrProof from "./proofs/SchnorrProof";
import * as Point from "./Point";
import * as Answer from "./Answer";
import * as Election from "./Election";
import * as Setup from "./Setup";
import { Hsignature } from "./math";

export type t = {
  election_uuid: string;
  election_hash: string;
  credential: string;
  answers: Array<Answer.Serialized.t>;
  signature: {
    hash: string;
    proof: Proof.Serialized.t;
  };
};

export function toJSON(ballot: t, election: Election.t): t {
  // The order of the JSON.stringify serialization
  // correspond to the order of insertion.
  let obj = {
    election_uuid: ballot.election_uuid,
    election_hash: ballot.election_hash,
    credential: ballot.credential,
    answers: election.questions.map((question, i) => {
      const answer = ballot.answers[i];
      if (Answer.Serialized.IsAnswerH(answer, question)) {
        return Answer.AnswerH.serialize(Answer.AnswerH.parse(answer));
      } else if (Answer.Serialized.IsAnswerNH(answer, question)) {
        return Answer.AnswerNH.serialize(Answer.AnswerNH.parse(answer));
      } else if (Answer.Serialized.IsAnswerL(answer, question)) {
        return Answer.AnswerL.serialize(Answer.AnswerL.parse(answer));
      } else {
        throw new Error("Unknown answer type");
      }
    }),
    signature: { hash: "", proof: { challenge: "", response: "" } },
  };

  if (ballot.signature) {
    obj["signature"] = {
      hash: ballot.signature.hash,
      proof: Proof.serialize(Proof.parse(ballot.signature.proof)),
    };
  }

  return obj;
}

export function verify(setup: Setup.t, ballot: t) {
  const { election, credentials } = setup;

  if (election.uuid !== ballot.election_uuid) {
    throw new Error("election_uuid is incorrect");
  }

  if (Election.fingerprint(election) !== ballot.election_hash) {
    throw new Error("election_hash is incorrect");
  }

  if (!Credential.find(credentials, ballot.credential)) {
    throw new Error("Credential not found");
  }

  const recomputedHash = b64hashWithoutSignature(ballot, election);
  if (ballot.signature.hash !== recomputedHash) {
    throw new Error("Ballot recomputed hash is incorrect");
  }

  const public_key = Point.parse(ballot.credential);
  const proof = Proof.parse(ballot.signature.proof);
  if (!SchnorrProof.verify(ballot.signature.hash, public_key, proof)) {
    throw new Error("Invalid signature");
  }

  for (let i = 0; i < election.questions.length; i++) {
    Answer.verify(
      election,
      ballot,
      election.questions[i],
      ballot.answers[i],
    );
  }
}

export function verifySignature(ballot: t, election: Election.t) {
  const recomputedHash = b64hashWithoutSignature(ballot, election);
  if (ballot.signature.hash !== recomputedHash) {
    throw new Error("Ballot recomputed hash is incorrect");
  }

  const proof = Proof.parse(ballot.signature.proof);
  const public_key = Point.parse(ballot.credential);
  const A = Point.compute_commitment(Point.g, public_key, proof);

  if (Hsignature(ballot.signature.hash, A) !== proof.nChallenge) {
    throw new Error("Invalid signature");
  }
}

export function hash(ballot: t) {
  return sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(JSON.stringify(ballot)));
}

export function b64hash(ballot: t) {
  return sjcl.codec.base64
    .fromBits(sjcl.hash.sha256.hash(JSON.stringify(ballot)))
    .replace(/=+$/, "");
}

export function b64hashWithoutSignature(ballot: t, election: Election.t) {
  const copy = Object.assign({}, toJSON(ballot, election));
  delete copy.signature;
  return b64hash(copy);
}
