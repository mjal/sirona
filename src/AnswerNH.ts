import * as Point from "./point";
import * as Proof from "./proof";
import * as Ciphertext from "./ciphertext";
import * as Election from "./election";
import * as Question from "./question";
import * as Ballot from "./ballot";
import { isValidPoint, formula, Hraweg } from "./math";

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
  return isValidPoint(ct.pAlpha) && isValidPoint(ct.pBeta);
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
