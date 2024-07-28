import { map2 } from "./utils";
import * as Proof from "./proof";
import * as Ciphertext from "./ciphertext";
import * as Election from "./election";
import * as Question from "./question";
import * as Ballot from "./ballot";
import * as Answer from "./Answer";
import * as Point from "./point";
import {
  L,
  mod,
  formula2,
  Hiprove,
  Hbproof0,
  Hbproof1,
} from "./math";

// -- Types

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

// -- Parse and serialize

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

// -- Check

export function verify(
  election: Election.t,
  electionFingerprint: string,
  ballot: Ballot.t,
  question: Question.QuestionH.t,
  answer: Serialized.t,
): boolean {
  if (!checkValidPoints(question, answer)) {
    throw new Error("Invalid curve points");
  }
  if (
    !checkIndividualProofs(
      election,
      electionFingerprint,
      ballot,
      question,
      answer,
    )
  ) {
    throw new Error("Invalid individual proofs");
  }
  if (question.blank) {
    if (
      !checkBlankProof(election, electionFingerprint, ballot, question, answer)
    ) {
      throw new Error("Invalid blank proof");
    }
    if (
      !checkOverallProofWithBlank(
        election,
        electionFingerprint,
        ballot,
        question,
        answer,
      )
    ) {
      throw new Error("Invalid blank proof");
    }
  } else {
    if (
      !checkOverallProofWithoutBlank(
        election,
        electionFingerprint,
        ballot,
        question,
        answer,
      )
    ) {
      throw new Error("Invalid overall proof (without blank vote)");
    }
  }
  return true;
}

export function checkValidPoints(
  question: Question.QuestionH.t,
  answer: Serialized.t,
): boolean {
  for (let j = 0; j < question.answers.length; j++) {
    const ct = Ciphertext.parse(answer.choices[j]);
    if (!Point.isValid(ct.pAlpha) || !Point.isValid(ct.pBeta)) {
      return false;
    }
  }
  return true;
}

export function checkIndividualProofs(
  election: Election.t,
  electionFingerprint: string,
  ballot: Ballot.t,
  question: Question.QuestionH.t,
  answer: Serialized.t,
): boolean {
  const pY = Point.parse(election.public_key);
  const S = `${electionFingerprint}|${ballot.credential}`;
  const a = Answer.AnswerH.parse(answer);
  for (let j = 0; j < question.answers.length + (question.blank ? 1 : 0); j++) {
    if (
      !Proof.checkIndividualProof(
        S,
        a.aazIndividualProofs[j],
        pY,
        a.aeChoices[j],
      )
    ) {
      return false;
    }
  }
  return true;
}

export function checkOverallProofWithoutBlank(
  election: Election.t,
  electionFingerprint: string,
  ballot: Ballot.t,
  question: Question.QuestionH.t,
  answer: Serialized.t,
): boolean {
  const pY = Point.parse(election.public_key);
  const a = Answer.AnswerH.parse(answer);
  const sumc = Ciphertext.combine(a.aeChoices);
  const nSumChallenges = a.azOverallProof.reduce(
    (acc: bigint, proof: Proof.t) => mod(acc + proof.nChallenge, L),
    0n,
  );

  let commitments = [];
  for (let j = 0; j <= question.max - question.min; j++) {
    const [pA, pB] = formula2(
      pY,
      sumc.pAlpha,
      sumc.pBeta,
      a.azOverallProof[j].nChallenge,
      a.azOverallProof[j].nResponse,
      question.min + j,
    );
    commitments.push(pA, pB);
  }

  let S = `${electionFingerprint}|${ballot.credential}|`;
  S += answer.choices.map(Ciphertext.Serialized.toString).join(",");

  return Hiprove(S, sumc.pAlpha, sumc.pBeta, ...commitments) === nSumChallenges;
}

export function checkOverallProofWithBlank(
  election: Election.t,
  electionFingerprint: string,
  ballot: Ballot.t,
  question: Question.QuestionH.t,
  answer: Serialized.t,
): boolean {
  const pY = Point.parse(election.public_key);
  const a = Answer.AnswerH.parse(answer);
  const sumc = Ciphertext.combine(a.aeChoices.slice(1));

  let commitments = [];
  const [pA, pB] = formula2(
    pY,
    a.aeChoices[0].pAlpha,
    a.aeChoices[0].pBeta,
    a.azOverallProof[0].nChallenge,
    a.azOverallProof[0].nResponse,
    1,
  );
  commitments.push(pA, pB);
  for (let j = 1; j < question.max - question.min + 2; j++) {
    const [pA, pB] = formula2(
      pY,
      sumc.pAlpha,
      sumc.pBeta,
      a.azOverallProof[j].nChallenge,
      a.azOverallProof[j].nResponse,
      question.min + j - 1,
    );
    commitments.push(pA, pB);
  }

  const nSumChallenges = a.azOverallProof.reduce(
    (acc, proof) => mod(acc + BigInt(proof.nChallenge), L),
    0n,
  );

  let S = `${electionFingerprint}|${ballot.credential}|`;
  S += answer.choices.map(Ciphertext.Serialized.toString).join(",");

  return Hbproof1(S, ...commitments) === nSumChallenges;
}

export function checkBlankProof(
  election: Election.t,
  electionFingerprint: string,
  ballot: Ballot.t,
  _question: Question.QuestionH.t,
  answer: Serialized.t,
): boolean {
  const pY = Point.parse(election.public_key);
  const a = Answer.AnswerH.parse(answer);
  const sumc = Ciphertext.combine(a.aeChoices.slice(1));
  const nSumChallenges = a.azBlankProof.reduce(
    (acc, proof) => mod(acc + BigInt(proof.nChallenge), L),
    0n,
  );

  const [pA0, pB0] = formula2(
    pY,
    a.aeChoices[0].pAlpha,
    a.aeChoices[0].pBeta,
    a.azBlankProof[0].nChallenge,
    a.azBlankProof[0].nResponse,
    0,
  );
  const [pAS, pBS] = formula2(
    pY,
    sumc.pAlpha,
    sumc.pBeta,
    a.azBlankProof[1].nChallenge,
    a.azBlankProof[1].nResponse,
    0,
  );

  let S = `${electionFingerprint}|${ballot.credential}|`;
  S += answer.choices.map(Ciphertext.Serialized.toString).join(",");
  return Hbproof0(S, ...[pA0, pB0, pAS, pBS]) === nSumChallenges;
}
