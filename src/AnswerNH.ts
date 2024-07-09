import * as Proof from "./proof";
import * as Ciphertext from "./ciphertext";
import * as Election from "./election";
import * as Question from "./question";
import * as Ballot from "./ballot";
import { isValidPoint } from "./math";

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

export function check(
  election: Election.t,
  electionFingerprint: string,
  ballot: Ballot.t,
  question: Question.QuestionNH.t,
  answer: Serialized.t,
) {
  if (!checkValidPoints(answer)) {
    throw new Error("Invalid curve points");
  }
  throw new Error("NonHomomorphic questions not fully implemented yet");

  return true;
}

export function checkValidPoints(answer: Serialized.t) {
  const ct = Ciphertext.parse(answer.choices);
  return (isValidPoint(ct.pAlpha) && isValidPoint(ct.pBeta));
}
