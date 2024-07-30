import { map2, map3 } from "./utils";
import * as Proof from "./Proof";
import * as NonZeroProof from "./ProofNonZero";
import * as Ciphertext from "./Ciphertext";
import * as Election from "./Election";
import * as Question from "./Question";
import * as Ballot from "./Ballot";
import * as Point from "./Point";
import {
  L,
  mod,
  formula,
  formula2,
  Hiprove,
  Hlproof,
  Hnonzero,
} from "./math";

export type t = {
  choices: Array<Array<Ciphertext.t>>;
  individual_proofs: Array<Array<Array<Proof.t>>>;
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

export function parse(answer: Serialized.t): t {
  return {
    choices: map2(answer.choices, Ciphertext.parse),
    individual_proofs: map3(answer.individual_proofs, Proof.parse),
    overall_proof: Proof.parse(answer.overall_proof),
    list_proofs: map2(answer.list_proofs, Proof.parse),
    nonzero_proof: NonZeroProof.parse(answer.nonzero_proof),
  };
}

export function verify(
  election: Election.t,
  ballot: Ballot.t,
  question: Question.QuestionL.t,
  serializedAnswer: Serialized.t,
): boolean {
  const answer = parse(serializedAnswer);

  for (let i = 0; i < question.value.answers.length; i++) {
    for (let j = 0; j < question.value.answers[i].length; j++) {
      if (Ciphertext.isValid(answer.choices[i][j]) === false) {
        throw new Error("Invalid curve point");
      }
    }
  }

  if (
    !checkIndividualProofs(
      election,
      ballot,
      question,
      answer,
    )
  ) {
    throw new Error("Invalid individual proofs");
  }

  if (
    !checkOverallProofLists(
      election,
      ballot,
      question,
      answer,
    )
  ) {
    throw new Error("Invalid overall proof (lists)");
  }

  if (
    !checkNonZeroProof(election, ballot, question, answer)
  ) {
    throw new Error("Invalid non zero proof (lists)");
  }

  if (
    !checkListProofs(election, ballot, question, answer)
  ) {
    throw new Error("Invalid list proof");
  }

  return true;
}

export function checkIndividualProofs(
  election: Election.t,
  ballot: Ballot.t,
  question: Question.QuestionL.t,
  answer: t,
): boolean {
  const pY = Point.parse(election.public_key);

  const S = `${election.fingerprint}|${ballot.credential}`;
  for (let j = 0; j < question.value.answers.length; j++) {
    for (let k = 0; k < question.value.answers[j].length; k++) {
      if (
        !Proof.checkIndividualProof(
          S,
          answer.individual_proofs[j][k],
          pY,
          answer.choices[j][k],
        )
      ) {
        return false;
      }
    }
  }
  return true;
}

function checkOverallProofLists(
  election: Election.t,
  ballot: Ballot.t,
  _question: Question.QuestionL.t,
  answer: t,
): boolean {
  const pY = Point.parse(election.public_key);
  const sumc = Ciphertext.combine(answer.choices.map((c) => c[0]));

  const [pA, pB] = formula2(
    pY,
    sumc.pAlpha,
    sumc.pBeta,
    answer.overall_proof.nChallenge,
    answer.overall_proof.nResponse,
    1,
  );

  let S = `${election.fingerprint}|${ballot.credential}|`;
  S += answer.choices
    .map((cs: any) => {
      return cs.map(Ciphertext.toString).join(",");
    })
    .join(",");

  return (
    Hiprove(S, sumc.pAlpha, sumc.pBeta, pA, pB) === answer.overall_proof.nChallenge
  );
}

function checkNonZeroProof(
  election: Election.t,
  ballot: Ballot.t,
  _question: Question.QuestionL.t,
  answer: t,
): boolean {
  const pY = Point.parse(election.public_key);

  const ct = Ciphertext.combine(
    answer.choices.map((choices) => {
      return Ciphertext.combine(choices.slice(1));
    }),
  );

  const A0 = answer.nonzero_proof.pCommitment;
  const c = answer.nonzero_proof.nChallenge;
  const [t1, t2] = answer.nonzero_proof.nResponse;

  if (Point.isEqual(A0, Point.zero)) {
    return false;
  }

  const A1 = formula(ct.pAlpha, t1, Point.g, t2);
  const A2 = formula(ct.pBeta, t1, pY, t2).add(A0.multiply(c));

  let S = `${election.fingerprint}|${ballot.credential}|`;
  S += answer.choices
    .map((cs: any) => {
      return cs.map(Ciphertext.toString).join(",");
    })
    .join(",");

  return Hnonzero(S, A0, A1, A2) === c;
}

function checkListProofs(
  election: Election.t,
  ballot: Ballot.t,
  question: Question.QuestionL.t,
  answer: t,
): boolean {
  const pY = Point.parse(election.public_key);

  for (let i = 0; i < question.value.answers.length; i++) {
    const proofs = answer.list_proofs[i];
    const ct0 = answer.choices[i][0];
    const ct = Ciphertext.combine(answer.choices[i].slice(1));

    const [A0, B0] = formula2(
      pY,
      ct0.pAlpha,
      ct0.pBeta,
      proofs[0].nChallenge,
      proofs[0].nResponse,
      1,
    );

    const A1 = formula(Point.g, proofs[1].nResponse, ct.pAlpha, proofs[1].nChallenge);
    const B1 = formula(pY, proofs[1].nResponse, ct.pBeta, proofs[1].nChallenge);

    let S = `${election.fingerprint}|${ballot.credential}|`;
    S += answer.choices
      .map((cs: any) => {
        return cs.map(Ciphertext.toString).join(",");
      })
      .join(",");

    const nSumChallenges = mod(proofs[0].nChallenge + proofs[1].nChallenge, L);

    return (
      answer.choices[i].length === question.value.answers[i].length &&
      Hlproof(S, A0, B0, A1, B1) === nSumChallenges
    );
  }
}
