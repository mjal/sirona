import { map2 } from './utils';
import * as Proof from './proof';
import * as Ciphertext from './ciphertext';
import * as Election from './election';
import * as Question from './question';
import * as Ballot from './ballot';
import * as Answer from './Answer';
import * as Point from './point';
import { logBallot } from "./logger";
import {
  L,
  mod,
  parsePoint,
  isValidPoint,
  formula2,
  Hiprove,
  Hbproof0,
  Hbproof1
} from "./math";

// -- Types

export type t = {
  aeChoices: Array<Ciphertext.t>;
  aazIndividualProofs: Array<Array<Proof.t>>;
  azOverallProof: Array<Proof.t>;
  azBlankProof?: Array<Proof.t>;
}

export namespace Serialized {
  export type t = {
    choices: Array<Ciphertext.Serialized.t>;
    individual_proofs: Array<Array<Proof.Serialized.t>>;
    overall_proof: Array<Proof.Serialized.t>;
    blank_proof?: Array<Proof.Serialized.t>;
  };
}

// -- Parse and serialize

export function parse(answer: Serialized.t) : t {
  let obj : t = {
    aeChoices: answer.choices.map(Ciphertext.parse),
    aazIndividualProofs: map2(answer.individual_proofs, Proof.parse),
    azOverallProof: answer.overall_proof.map(Proof.parse),
  };
  if (answer.blank_proof) {
    obj.azBlankProof = answer.blank_proof.map(Proof.parse);
  }
  return obj;
}

export function serialize(answer: t) : Serialized.t {
  let obj : Serialized.t = {
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

export function checkValidPoints(
  ballot: Ballot.t,
  question: Question.QuestionH.t,
  answer: Serialized.t
) {
  for (let j = 0; j < question.answers.length; j++) {
    const ct = Ciphertext.parse(answer.choices[j]);
    logBallot(
      ballot.signature.hash,
      isValidPoint(ct.pAlpha) && isValidPoint(ct.pBeta),
      "Encrypted choices alpha,beta are valid curve points",
    );
  }
}

export function checkIndividualProofs(
  election: Election.t,
  electionFingerprint: string,
  ballot: Ballot.t,
  question: Question.QuestionH.t,
  answer: Serialized.t
) {
  const pY = parsePoint(election.public_key);
  const S = `${electionFingerprint}|${ballot.credential}`;
  const a = Answer.AnswerH.parse(answer);
  for (let j = 0; j < question.answers.length + (question.blank ? 1 : 0); j++) {
    let bCheckResult = Proof.checkIndividualProof(S,
      a.aazIndividualProofs[j],
      pY,
      a.aeChoices[j]
    );
    logBallot(ballot.signature.hash, bCheckResult, "Valid individual proof");
  }
}

export function checkOverallProofWithoutBlank(
  election: Election.t,
  electionFingerprint: string,
  ballot: Ballot.t,
  question: Question.QuestionH.t,
  answer: Serialized.t
) {
  const pY = parsePoint(election.public_key);
  const a = Answer.AnswerH.parse(answer);

  const sumc = a.aeChoices.reduce((acc, c) => {
    return {
      pAlpha: acc.pAlpha.add(c.pAlpha),
      pBeta: acc.pBeta.add(c.pBeta),
    };
  }, Ciphertext.zero);

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
  S += answer.choices.map((c) => `${c.alpha},${c.beta}`).join(",");
  const nH = Hiprove(S, sumc.pAlpha, sumc.pBeta, ...commitments);

  logBallot(
    ballot.signature.hash,
    nSumChallenges === nH,
    "Valid overall proof (without blank vote)",
  );
}

export function checkOverallProofWithBlank(
  election: Election.t,
  electionFingerprint: string,
  ballot: Ballot.t,
  question: Question.QuestionH.t,
  answer: Serialized.t
) {
  const pY = parsePoint(election.public_key);
  const a = Answer.AnswerH.parse(answer);

  const pAlphaS = a.aeChoices.slice(1).reduce((acc, c) => acc.add(c.pAlpha), Point.zero);
  const pBetaS = a.aeChoices.slice(1).reduce((acc, c) => acc.add(c.pBeta), Point.zero);

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
      pAlphaS,
      pBetaS,
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
  S += answer.choices.map((c) => `${c.alpha},${c.beta}`).join(",");
  const nH = Hbproof1(S, ...commitments);

  logBallot(
    ballot.signature.hash,
    nSumChallenges === nH,
    "Valid overall proof (with blank vote)",
  );
}

export function checkBlankProof(
  election: Election.t,
  electionFingerprint: string,
  ballot: Ballot.t,
  _question: Question.QuestionH.t,
  answer: Serialized.t
) {
  const pY = parsePoint(election.public_key);
  const a = Answer.AnswerH.parse(answer);

  const pAlphaS = a.aeChoices.slice(1).reduce((acc, c) => acc.add(c.pAlpha), Point.zero);
  const pBetaS = a.aeChoices.slice(1).reduce((acc, c) => acc.add(c.pBeta), Point.zero);

  const nSumChallenges = a.azBlankProof.reduce(
    (acc, proof) => mod(acc + BigInt(proof.nChallenge), L),
    0n,
  );

  const [pA0, pB0] = formula2(pY, a.aeChoices[0].pAlpha, a.aeChoices[0].pBeta,
                              a.azBlankProof[0].nChallenge, a.azBlankProof[0].nResponse, 0);
  const [pAS, pBS] = formula2(pY, pAlphaS, pBetaS,
                              a.azBlankProof[1].nChallenge, a.azBlankProof[1].nResponse, 0);

  let S = `${electionFingerprint}|${ballot.credential}|`;
  S += answer.choices.map((c) => `${c.alpha},${c.beta}`).join(",");
  const nH = Hbproof0(S, ...[pA0, pB0, pAS, pBS]);

  logBallot(
    ballot.signature.hash,
    nSumChallenges === nH,
    "Valid blank proof",
  );
}

export function check(
  election: Election.t,
  electionFingerprint: string,
  ballot: Ballot.t,
  question: Question.QuestionH.t,
  answer: Serialized.t
) {

  checkValidPoints(ballot, question, answer);

  checkIndividualProofs(
    election, electionFingerprint,
    ballot, question, answer);

  if (question.blank) {
    checkBlankProof(
      election, electionFingerprint,
      ballot, question, answer);
    checkOverallProofWithBlank(
      election, electionFingerprint,
      ballot, question, answer);
  } else {
    checkOverallProofWithoutBlank(
      election, electionFingerprint,
      ballot, question, answer);
  }
}

