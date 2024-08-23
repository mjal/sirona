import sjcl from "sjcl";
import * as Proof from "./Proof";
import * as Point from "./Point";
import * as Answer from "./Answer";
import * as Election from "./Election";
import { g, formula, Hsignature } from "./math";

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

export function toJSON(ballot: t, election: Election.t) : t {
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

  if (ballot.signature.hash) {
    obj["signature"] = {
      hash: ballot.signature.hash,
      proof: Proof.serialize(Proof.parse(ballot.signature.proof)),
    };
  }

  return obj;
}

export function verify(state: any, ballot: t) {
  const election = state.setup.election;
  checkMisc(ballot, election);
  checkCredential(ballot, state.setup.credentials);
  checkSignature(ballot, election);

  for (let i = 0; i < state.setup.election.questions.length; i++) {
    Answer.verify(
      election,
      ballot,
      state.setup.election.questions[i],
      ballot.answers[i],
    );
  }
}

function checkMisc(ballot: t, election: Election.t) {
  if (
    !(
      election.uuid === ballot.election_uuid &&
      Election.fingerprint(election) === ballot.election_hash
    )
  ) {
    throw new Error("election_uuid or election_hash is incorrect");
  }
}

export function hashWithoutSignature(ballot: t, election: Election.t) {
  const copy = Object.assign({}, toJSON(ballot, election));
  delete copy.signature;
  const serialized = JSON.stringify(copy);
  const hash = sjcl.codec.base64.fromBits(sjcl.hash.sha256.hash(serialized));
  return hash.replace(/=+$/, "");
}

function checkCredential(ballot: t, credentials: string[]) {
  if (
    credentials.map((line) => line.split(",")[0]).indexOf(ballot.credential) ===
    -1
  ) {
    throw new Error("Credential is not valid");
  }
}

export function checkSignature(ballot: t, election: Election.t) {
  if (ballot.signature.hash !== hashWithoutSignature(ballot, election)) {
    throw new Error("Hash without signature is incorrect");
  }

  const signature = ballot.signature;
  const nChallenge = BigInt(signature.proof.challenge);
  const nResponse = BigInt(signature.proof.response);

  const pA = formula(g, nResponse, Point.parse(ballot.credential), nChallenge);
  const nH = Hsignature(signature.hash, pA);

  if (nH !== nChallenge) {
    throw new Error("Invalid signature");
  }
}

export function hash(ballot: t) {
  return sjcl.codec.hex
    .fromBits(sjcl.hash.sha256.hash(JSON.stringify(ballot)));
}

export function b64hash(ballot: t) {
  return sjcl.codec.base64
    .fromBits(sjcl.hash.sha256.hash(JSON.stringify(ballot)))
    .replace(/=+$/, "");
}
