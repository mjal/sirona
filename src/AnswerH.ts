import { map2 } from "./utils";
import * as Proof from "./Proof";
import * as Ciphertext from "./Ciphertext";
import * as Election from "./Election";
import * as Question from "./Question";
import * as Ballot from "./Ballot";
import * as Point from "./Point";
import { L, mod, formula2, Hiprove, Hbproof0, Hbproof1 } from "./math";

export type t = {
  aeChoices: Array<Ciphertext.t>;
  aazIndividualProofs: Array<Array<Proof.t>>;
  azOverallProof: Array<Proof.t>;
  azBlankProof?: Array<Proof.t>;
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
    aeChoices: answer.choices.map(Ciphertext.parse),
    aazIndividualProofs: map2(answer.individual_proofs, Proof.parse),
    azOverallProof: answer.overall_proof.map(Proof.parse),
  };
  if (answer.blank_proof) {
    obj.azBlankProof = answer.blank_proof.map(Proof.parse);
  }
  return obj;
}

export function serialize(answer: t): Serialized.t {
  let obj: Serialized.t = {
    choices: answer.aeChoices.map(Ciphertext.serialize),
    individual_proofs: map2(answer.aazIndividualProofs, Proof.serialize),
    overall_proof: answer.azOverallProof.map(Proof.serialize),
  };
  if (answer.azBlankProof) {
    obj.blank_proof = answer.azBlankProof.map(Proof.serialize);
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
    if (Ciphertext.isValid(answer.aeChoices[j]) === false) {
      return false;
    }
  }

  if (!checkIndividualProofs(election, ballot, question, answer)) {
    throw new Error("Invalid individual proofs");
  }
  if (question.blank) {
    if (!checkBlankProof(election, ballot, question, answer)) {
      throw new Error("Invalid blank proof");
    }
    if (!checkOverallProofWithBlank(election, ballot, question, answer)) {
      throw new Error("Invalid blank proof");
    }
  } else {
    if (!checkOverallProofWithoutBlank(election, ballot, question, answer)) {
      throw new Error("Invalid overall proof (without blank vote)");
    }
  }
  return true;
}

export function checkIndividualProofs(
  election: Election.t,
  ballot: Ballot.t,
  question: Question.QuestionH.t,
  answer: t,
): boolean {
  const pY = Point.parse(election.public_key);
  const S = `${Election.fingerprint(election)}|${ballot.credential}`;
  for (let j = 0; j < question.answers.length + (question.blank ? 1 : 0); j++) {
    if (
      !Proof.checkIndividualProof(
        S,
        answer.aazIndividualProofs[j],
        pY,
        answer.aeChoices[j],
      )
    ) {
      return false;
    }
  }
  return true;
}

export function checkOverallProofWithoutBlank(
  election: Election.t,
  ballot: Ballot.t,
  question: Question.QuestionH.t,
  answer: t,
): boolean {
  const pY = Point.parse(election.public_key);
  const sumc = Ciphertext.combine(answer.aeChoices);
  const nSumChallenges = answer.azOverallProof.reduce(
    (acc: bigint, proof: Proof.t) => mod(acc + proof.nChallenge, L),
    0n,
  );

  let commitments = [];
  for (let j = 0; j <= question.max - question.min; j++) {
    const [pA, pB] = formula2(
      pY,
      sumc.pAlpha,
      sumc.pBeta,
      answer.azOverallProof[j].nChallenge,
      answer.azOverallProof[j].nResponse,
      question.min + j,
    );
    commitments.push(pA, pB);
  }

  let S = `${Election.fingerprint(election)}|${ballot.credential}|`;
  S += answer.aeChoices.map(Ciphertext.toString).join(",");

  return Hiprove(S, sumc.pAlpha, sumc.pBeta, ...commitments) === nSumChallenges;
}

export function checkOverallProofWithBlank(
  election: Election.t,
  ballot: Ballot.t,
  question: Question.QuestionH.t,
  answer: t,
): boolean {
  const pY = Point.parse(election.public_key);
  const sumc = Ciphertext.combine(answer.aeChoices.slice(1));

  let commitments = [];
  const [pA, pB] = formula2(
    pY,
    answer.aeChoices[0].pAlpha,
    answer.aeChoices[0].pBeta,
    answer.azOverallProof[0].nChallenge,
    answer.azOverallProof[0].nResponse,
    1,
  );
  commitments.push(pA, pB);
  for (let j = 1; j < question.max - question.min + 2; j++) {
    const [pA, pB] = formula2(
      pY,
      sumc.pAlpha,
      sumc.pBeta,
      answer.azOverallProof[j].nChallenge,
      answer.azOverallProof[j].nResponse,
      question.min + j - 1,
    );
    commitments.push(pA, pB);
  }

  const nSumChallenges = answer.azOverallProof.reduce(
    (acc, proof) => mod(acc + BigInt(proof.nChallenge), L),
    0n,
  );

  let S = `${Election.fingerprint(election)}|${ballot.credential}|`;
  S += answer.aeChoices.map(Ciphertext.toString).join(",");

  return Hbproof1(S, ...commitments) === nSumChallenges;
}

export function checkBlankProof(
  election: Election.t,
  ballot: Ballot.t,
  _question: Question.QuestionH.t,
  answer: t,
): boolean {
  const pY = Point.parse(election.public_key);
  const sumc = Ciphertext.combine(answer.aeChoices.slice(1));
  const nSumChallenges = answer.azBlankProof.reduce(
    (acc, proof) => mod(acc + BigInt(proof.nChallenge), L),
    0n,
  );

  const [pA0, pB0] = formula2(
    pY,
    answer.aeChoices[0].pAlpha,
    answer.aeChoices[0].pBeta,
    answer.azBlankProof[0].nChallenge,
    answer.azBlankProof[0].nResponse,
    0,
  );
  const [pAS, pBS] = formula2(
    pY,
    sumc.pAlpha,
    sumc.pBeta,
    answer.azBlankProof[1].nChallenge,
    answer.azBlankProof[1].nResponse,
    0,
  );

  let S = `${Election.fingerprint(election)}|${ballot.credential}|`;
  S += answer.aeChoices.map(Ciphertext.toString).join(",");
  return Hbproof0(S, ...[pA0, pB0, pAS, pBS]) === nSumChallenges;
}
