import * as Point from "./Point";
import * as Proof from "./Proof";
import * as ElGamal from "./ElGamal";
import * as Election from "./Election";
import * as Question from "./Question";
import * as Ballot from "./Ballot";
import { Hraweg } from "./math";

export type t = {
  choices: ElGamal.t;
  proof: Proof.t;
};

export type serialized_t = {
  choices: ElGamal.serialized_t;
  proof: Proof.serialized_t;
};

export function parse(answer: serialized_t): t {
  return {
    choices: ElGamal.parse(answer.choices),
    proof: Proof.parse(answer.proof),
  };
}

export function serialize(answer: t): serialized_t {
  return {
    choices: ElGamal.serialize(answer.choices),
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

  if (ElGamal.isValid(answer.choices) === false) {
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
  const y = election.public_key;
  const { choices, proof } = answer;
  const A = Point.commit(Point.g, choices.alpha, proof);
  const S = `${Election.fingerprint(election)}|${ballot.credential}`;

  return Hraweg(S, y, choices.alpha, choices.beta, A) === proof.challenge;
}
