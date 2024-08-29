import { map2 } from "./utils";
import * as Proof from "./Proof";
import * as IndividualProof from "./proofs/IndividualProof";
import * as BlankProof from "./proofs/BlankProof";
import * as Ciphertext from "./Ciphertext";
import * as Election from "./Election";
import * as Question from "./Question";
import * as Ballot from "./Ballot";

export type t = {
  choices: Array<Ciphertext.t>;
  individual_proofs: Array<Array<Proof.t>>;
  overall_proof: Array<Proof.t>;
  blank_proof?: Array<Proof.t>;
};

export namespace Serialized {
  export type t = {
    choices: Array<Ciphertext.Serialized.t>;
    individual_proofs: Array<Array<Proof.Serialized.t>>;
    overall_proof: Array<Proof.Serialized.t>;
    blank_proof?: Array<Proof.Serialized.t>;
  };
}

export function parse(answer: Serialized.t): t {
  let obj: t = {
    choices: answer.choices.map(Ciphertext.parse),
    individual_proofs: map2(answer.individual_proofs, Proof.parse),
    overall_proof: answer.overall_proof.map(Proof.parse),
  };
  if (answer.blank_proof) {
    obj.blank_proof = answer.blank_proof.map(Proof.parse);
  }
  return obj;
}

export function serialize(answer: t): Serialized.t {
  let obj: Serialized.t = {
    choices: answer.choices.map(Ciphertext.serialize),
    individual_proofs: map2(answer.individual_proofs, Proof.serialize),
    overall_proof: answer.overall_proof.map(Proof.serialize),
  };
  if (answer.blank_proof) {
    obj.blank_proof = answer.blank_proof.map(Proof.serialize);
  }
  return obj;
}

export function verify(
  election: Election.t,
  ballot: Ballot.t,
  question: Question.QuestionH.t,
  serializedAnswer: Serialized.t,
): boolean {
  const answer = parse(serializedAnswer);

  for (let j = 0; j < question.answers.length; j++) {
    if (Ciphertext.isValid(answer.choices[j]) === false) {
      return false;
    }
  }

  for (let j = 0; j < question.answers.length + (question.blank ? 1 : 0); j++) {
    if (
      !IndividualProof.verify(
        election,
        ballot.credential,
        answer.individual_proofs[j],
        answer.choices[j],
        0, 1
      )
    ) {
      throw new Error("Invalid individual proofs");
    }
  }

  if (question.blank) {
    if (
      !BlankProof.BlankProof.verify(
        election,
        ballot.credential,
        answer)
      ) {
      throw new Error("Invalid blank proof");
    }
    if (
      !BlankProof.OverallProof.verify(
        election,
        ballot.credential,
        question,
        answer)
      ) {
      throw new Error("Invalid overall proof");
    }
  } else {
    const eg = Ciphertext.combine(answer.choices);
    let suffix = answer.choices.map(Ciphertext.toString).join(",");
    if (
      !IndividualProof.verify(
        election,
        ballot.credential + "|" + suffix,
        answer.overall_proof,
        eg,
        question.min, question.max
      )
    ) {
      throw new Error("Invalid overall proof (without blank vote)");
    }
  }

  return true;
}
