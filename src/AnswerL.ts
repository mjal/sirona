import { map2, map3 } from "./utils";
import * as Proof from "./proof";
import * as NonZeroProof from "./nonZeroProof";
import * as Ciphertext from "./ciphertext";
import * as Election from "./election";
import * as Question from "./question";
import * as Ballot from "./ballot";
import * as Answer from "./Answer";
import * as Point from "./point";
import {
  g,
  L,
  mod,
  parsePoint,
  isValidPoint,
  formula,
  formula2,
  Hiprove,
  Hlproof,
  Hnonzero,
} from "./math";

// -- Types

export type t = {
  choices: Array<Array<Ciphertext.t>>;
  individual_proofs: Array<Array<Proof.t>>;
  overall_proof: Proof.t;
  list_proofs: Array<Proof.t>;
  nonzero_proof: NonZeroProof.t;
};

export namespace Serialized {
  export type t = {
    choices: Array<Array<Ciphertext.Serialized.t>>;
    individual_proofs: Array<Array<Array<Proof.Serialized.t>>>;
    overall_proof: Proof.Serialized.t;
    list_proofs: Array<Array<Proof.Serialized.t>>;
    nonzero_proof: NonZeroProof.Serialized.t;
  };
}

// -- Parse and serialize
//
export function parse(answer: Serialized.t): t {
  return {
    choices: map2(answer.choices, Ciphertext.parse),
    individual_proofs: map3(answer.individual_proofs, Proof.parse),
    overall_proof: Proof.parse(answer.overall_proof),
    list_proofs: map2(answer.list_proofs, Proof.parse),
    nonzero_proof: NonZeroProof.parse(answer.nonzero_proof),
  };
}

// -- Check

export function check(
  election: Election.t,
  electionFingerprint: string,
  ballot: Ballot.t,
  question: Question.QuestionL.t,
  answer: Serialized.t,
) : boolean {
  if (!checkValidPoints(question, answer)) {
    throw new Error("Invalid curve points");
  }
  if (!checkIndividualProofs(
    election,
    electionFingerprint,
    ballot,
    question,
    answer)) {
    throw new Error("Invalid individual proofs");
  }
  if (!checkOverallProofLists(
    election,
    electionFingerprint,
    ballot,
    question,
    answer)) {
      throw new Error("Invalid overall proof (lists)");
  }
  if (!checkNonZeroProof(election, electionFingerprint, ballot, question, answer)) {
    throw new Error("Invalid non zero proof (lists)");
  }
  if (!checkListProofs(election, electionFingerprint, ballot, question, answer)) {
    throw new Error("Invalid list proof");
  }

  return true;
}

export function checkValidPoints(
  question: Question.QuestionL.t,
  answer: Serialized.t,
) : boolean {
  for (let i = 0; i < question.value.answers.length; i++) {
    for (let j = 0; j < question.value.answers[i].length; j++) {
      const ct = Ciphertext.parse(answer.choices[i][j]);
      if (!isValidPoint(ct.pAlpha) || !isValidPoint(ct.pBeta)) {
        return false;
      }
    }
  }
  return true;
}

export function checkIndividualProofs(
  election: Election.t,
  electionFingerprint: string,
  ballot: Ballot.t,
  question: Question.QuestionL.t,
  answer: Serialized.t,
) : boolean {
  const pY = parsePoint(election.public_key);

  const S = `${electionFingerprint}|${ballot.credential}`;
  // TODO: parseAnswerL
  const aaeChoices = map2(answer.choices, Ciphertext.parse);
  const aaazIndividualProofs = map3(answer.individual_proofs, Proof.parse);
  for (let j = 0; j < question.value.answers.length; j++) {
    for (let k = 0; k < question.value.answers[j].length; k++) {
      if (!Proof.checkIndividualProof(
        S,
        aaazIndividualProofs[j][k],
        pY,
        aaeChoices[j][k],
      )) {
        return false;
      }
    }
  }
  return true;
}

function checkOverallProofLists(
  election: Election.t,
  electionFingerprint: string,
  ballot: Ballot.t,
  question: Question.QuestionL.t,
  answer: Serialized.t,
) : boolean {
  const pY = parsePoint(election.public_key);
  const a = Answer.AnswerL.parse(answer);

  const sumc = a.choices.reduce((acc, c) => {
    return {
      pAlpha: acc.pAlpha.add(c[0].pAlpha),
      pBeta: acc.pBeta.add(c[0].pBeta),
    };
  }, Ciphertext.zero);

  const [pA, pB] = formula2(
    pY,
    sumc.pAlpha,
    sumc.pBeta,
    a.overall_proof.nChallenge,
    a.overall_proof.nResponse,
    1,
  );

  let S = `${electionFingerprint}|${ballot.credential}|`;
  S += answer.choices
    .map((cs) => {
      return cs.map((c) => `${c.alpha},${c.beta}`).join(",");
    })
    .join(",");

  return (Hiprove(S, sumc.pAlpha, sumc.pBeta, pA, pB) === a.overall_proof.nChallenge);
}

function checkNonZeroProof(
  election: Election.t,
  electionFingerprint: string,
  ballot: Ballot.t,
  _question: Question.QuestionL.t,
  answer: Serialized.t,
) : boolean {
  const pY = parsePoint(election.public_key);
  const a = Answer.AnswerL.parse(answer);

  const ct = a.choices.reduce((acc, choices) => {
    const temp = choices.slice(1).reduce((acc, c) => {
      return {
        pAlpha: acc.pAlpha.add(c.pAlpha),
        pBeta: acc.pBeta.add(c.pBeta),
      };
    }, Ciphertext.zero);
    return {
      pAlpha: acc.pAlpha.add(temp.pAlpha),
      pBeta: acc.pBeta.add(temp.pBeta),
    };
  }, Ciphertext.zero);

  const A0 = a.nonzero_proof.pCommitment;
  const c = a.nonzero_proof.nChallenge;
  const [t1, t2] = a.nonzero_proof.nResponse;

  if (Point.serialize(A0) === Point.serialize(Point.zero)) {
    return false;
  }

  const A1 = formula(ct.pAlpha, t1, g, t2);
  const A2 = formula(ct.pBeta, t1, pY, t2).add(A0.multiply(c));

  let S = `${electionFingerprint}|${ballot.credential}|`;
  S += answer.choices
    .map((cs) => {
      return cs.map((c) => `${c.alpha},${c.beta}`).join(",");
    })
    .join(",");

  return (Hnonzero(S, A0, A1, A2) === c);
}

function checkListProofs(
  election: Election.t,
  electionFingerprint: string,
  ballot: Ballot.t,
  question: Question.QuestionL.t,
  answer: Serialized.t,
) : boolean {
  const pY = parsePoint(election.public_key);
  const a = Answer.AnswerL.parse(answer);

  for (let i = 0; i < question.value.answers.length; i++) {
    const proofs = a.list_proofs[i];
    const ct0 = a.choices[i][0];
    const ct = a.choices[i]
      .slice(1)
      .reduce(Ciphertext.combine, Ciphertext.zero);

    const [A0, B0] = formula2(
      pY,
      ct0.pAlpha,
      ct0.pBeta,
      proofs[0].nChallenge,
      proofs[0].nResponse,
      1,
    );

    const A1 = formula(g, proofs[1].nResponse, ct.pAlpha, proofs[1].nChallenge);
    const B1 = formula(pY, proofs[1].nResponse, ct.pBeta, proofs[1].nChallenge);

    let S = `${electionFingerprint}|${ballot.credential}|`;
    S += answer.choices
      .map((cs) => {
        return cs.map((c) => `${c.alpha},${c.beta}`).join(",");
      })
      .join(",");

    const nSumChallenges = mod(proofs[0].nChallenge + proofs[1].nChallenge, L);

    return (a.choices[i].length === question.value.answers[i].length
      && Hlproof(S, A0, B0, A1, B1) === nSumChallenges);
  }
}
