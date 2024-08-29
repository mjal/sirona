import { map2 } from "./utils";
import * as Proof from "./Proof";
import * as IndividualProof from "./proofs/IndividualProof";
import * as Ciphertext from "./Ciphertext";
import * as Election from "./Election";
import * as Question from "./Question";
import * as Ballot from "./Ballot";
import * as Point from "./Point";
import { L, mod, formula2, Hiprove, Hbproof0, Hbproof1 } from "./math";

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
    if (!verifyBlankProof(election, ballot, question, answer)) {
      throw new Error("Invalid blank proof");
    }
    if (!verifyOverallProofWithBlank(election, ballot, question, answer)) {
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

export function verifyOverallProofWithBlank(
  election: Election.t,
  ballot: Ballot.t,
  question: Question.QuestionH.t,
  answer: t,
): boolean {
  const pY = Point.parse(election.public_key);
  const sumc = Ciphertext.combine(answer.choices.slice(1));

  let commitments = [];
  const [pA, pB] = formula2(
    pY,
    answer.choices[0].pAlpha,
    answer.choices[0].pBeta,
    answer.overall_proof[0].nChallenge,
    answer.overall_proof[0].nResponse,
    1,
  );
  commitments.push(pA, pB);
  for (let j = 1; j < question.max - question.min + 2; j++) {
    const [pA, pB] = formula2(
      pY,
      sumc.pAlpha,
      sumc.pBeta,
      answer.overall_proof[j].nChallenge,
      answer.overall_proof[j].nResponse,
      question.min + j - 1,
    );
    commitments.push(pA, pB);
  }

  const nSumChallenges = answer.overall_proof.reduce(
    (acc, proof) => mod(acc + BigInt(proof.nChallenge), L),
    0n,
  );

  let S = `${Election.fingerprint(election)}|${ballot.credential}|`;
  S += answer.choices.map(Ciphertext.toString).join(",");

  return Hbproof1(S, ...commitments) === nSumChallenges;
}

export function verifyBlankProof(
  election: Election.t,
  ballot: Ballot.t,
  _question: Question.QuestionH.t,
  answer: t,
): boolean {
  const pY = Point.parse(election.public_key);
  const sumc = Ciphertext.combine(answer.choices.slice(1));
  const nSumChallenges = answer.blank_proof.reduce(
    (acc, proof) => mod(acc + BigInt(proof.nChallenge), L),
    0n,
  );

  const [pA0, pB0] = formula2(
    pY,
    answer.choices[0].pAlpha,
    answer.choices[0].pBeta,
    answer.blank_proof[0].nChallenge,
    answer.blank_proof[0].nResponse,
    0,
  );
  const [pAS, pBS] = formula2(
    pY,
    sumc.pAlpha,
    sumc.pBeta,
    answer.blank_proof[1].nChallenge,
    answer.blank_proof[1].nResponse,
    0,
  );

  let S = `${Election.fingerprint(election)}|${ballot.credential}|`;
  S += answer.choices.map(Ciphertext.toString).join(",");
  return Hbproof0(S, ...[pA0, pB0, pAS, pBS]) === nSumChallenges;
}
