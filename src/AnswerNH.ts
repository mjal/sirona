import * as Point from "./Point";
import * as Proof from "./Proof";
import * as Ciphertext from "./Ciphertext";
import * as Election from "./Election";
import * as Question from "./Question";
import * as Ballot from "./Ballot";
import { formula, Hraweg } from "./math";

// -- Types

export type t = {
  choices: Ciphertext.t;
  proof: Proof.t;
};

export namespace Serialized {
  export type t = {
    choices: Ciphertext.Serialized.t;
    proof: Proof.Serialized.t;
  };
}

// -- Check

export function verify(
  election: Election.t,
  electionFingerprint: string,
  ballot: Ballot.t,
  question: Question.QuestionNH.t,
  answer: Serialized.t,
) {
  if (!checkValidPoints(answer)) {
    throw new Error("Invalid curve points");
  }
  if (!checkProof(election, electionFingerprint, ballot, question, answer)) {
    throw new Error("Invalid proof");
  }
  return true;
}

function checkValidPoints(answer: Serialized.t) {
  const ct = Ciphertext.parse(answer.choices);
  return Point.isValid(ct.pAlpha) && Point.isValid(ct.pBeta);
}

function checkProof(
  election: Election.t,
  electionFingerprint: string,
  ballot: Ballot.t,
  _question: Question.QuestionNH.t,
  answer: Serialized.t,
) {
  const y = Point.parse(election.public_key);
  const ct = Ciphertext.parse(answer.choices);
  const proof = Proof.parse(answer.proof);
  const A = formula(Point.g, proof.nResponse, ct.pAlpha, proof.nChallenge);
  const S = `${electionFingerprint}|${ballot.credential}`;

  return Hraweg(S, y, ct.pAlpha, ct.pBeta, A) === proof.nChallenge;
}
