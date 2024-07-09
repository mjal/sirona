import * as Proof from './proof';
import * as Ciphertext from './ciphertext';
import * as Election from './election';
import * as Question from './question';
import * as Ballot from './ballot';
import { logBallot } from "./logger";
import {
  isValidPoint,
} from "./math";

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

export function checkValidPoints(
  ballot: Ballot.t,
  answer: Serialized.t
) {
  const ct = Ciphertext.parse(answer.choices);
  logBallot(
    ballot.signature.hash,
    isValidPoint(ct.pAlpha) && isValidPoint(ct.pBeta),
    "Encrypted choices alpha,beta are valid curve points",
  );
}

export function check(
  election: Election.t,
  electionFingerprint: string,
  ballot: Ballot.t,
  question: Question.QuestionH.t,
  answer: Serialized.t
) {
  checkValidPoints(ballot, answer);
}
