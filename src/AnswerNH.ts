import * as Point from "./Point";
import * as Proof from "./Proof";
import * as Ciphertext from "./Ciphertext";
import * as Election from "./Election";
import * as Question from "./Question";
import * as Ballot from "./Ballot";
import { formula, Hraweg } from "./math";


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


export function parse(answer: Serialized.t): t {
  return {
    choices: Ciphertext.parse(answer.choices),
    proof: Proof.parse(answer.proof),
  };
}


export function verify(
  election: Election.t,
  ballot: Ballot.t,
  question: Question.QuestionNH.t,
  serializedAnswer: Serialized.t,
) {
  const answer = parse(serializedAnswer);

  if (Ciphertext.isValid(answer.choices) === false) {
    throw new Error("Invalid curve points");
  }

  if (!verifyProof(election, ballot, question, answer)) {
    throw new Error("Invalid proof");
  }

  return true;
}

function verifyProof(
  election: Election.t,
  ballot: Ballot.t,
  _question: Question.QuestionNH.t,
  answer: t,
) {
  const y = Point.parse(election.public_key);
  const { choices, proof } = answer;
  const A = formula(Point.g, proof.nResponse, choices.pAlpha, proof.nChallenge);
  const S = `${election.fingerprint}|${ballot.credential}`;

  return Hraweg(S, y, choices.pAlpha, choices.pBeta, A) === proof.nChallenge;
}
