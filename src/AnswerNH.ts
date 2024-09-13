import * as Point from "./Point";
import * as Proof from "./Proof";
import * as Ciphertext from "./Ciphertext";
import * as Election from "./Election";
import * as Question from "./Question";
import * as Ballot from "./Ballot";
import { Hraweg } from "./math";

export type t = {
  choices: Ciphertext.t;
  proof: Proof.t;
};

export type serialized_t = {
  choices: Ciphertext.serialized_t;
  proof: Proof.serialized_t;
};

export function parse(answer: serialized_t): t {
  return {
    choices: Ciphertext.parse(answer.choices),
    proof: Proof.parse(answer.proof),
  };
}

export function serialize(answer: t): serialized_t {
  return {
    choices: Ciphertext.serialize(answer.choices),
    proof: Proof.serialize(answer.proof),
  };
}

export function verify(
  election: Election.t,
  ballot: Ballot.t,
  question: Question.QuestionNH.t,
  serializedAnswer: serialized_t,
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
  const A = Point.compute_commitment(Point.g, choices.pAlpha, proof);
  const S = `${Election.fingerprint(election)}|${ballot.credential}`;

  return Hraweg(S, y, choices.pAlpha, choices.pBeta, A) === proof.nChallenge;
}
