import { map2, map3 } from "./utils";
import * as Z from "./Z";
import * as Proof from "./Proof";
import * as IndividualProof from "./proofs/IndividualProof";
import * as NonZeroProof from "./ProofNonZero";
import * as Ciphertext from "./Ciphertext";
import * as Election from "./Election";
import * as Question from "./Question";
import * as Ballot from "./Ballot";
import * as Point from "./Point";
import { Hiprove, Hlproof, Hnonzero } from "./math";

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

export function serialize(answer: t): Serialized.t {
  return {
    choices: map2(answer.choices, Ciphertext.serialize),
    individual_proofs: map3(answer.individual_proofs, Proof.serialize),
    overall_proof: Proof.serialize(answer.overall_proof),
    list_proofs: map2(answer.list_proofs, Proof.serialize),
    nonzero_proof: NonZeroProof.serialize(answer.nonzero_proof),
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

  for (let j = 0; j < question.value.answers.length; j++) {
    for (let k = 0; k < question.value.answers[j].length; k++) {
      if (
        !IndividualProof.verify(
          election,
          ballot.credential,
          answer.individual_proofs[j][k],
          answer.choices[j][k],
          0,
          1,
        )
      ) {
        throw new Error("Invalid individual proofs");
      }
    }
  }

  const eg = Ciphertext.combine(answer.choices.map((c) => c[0]));
  let S = `${ballot.credential}|`;
  S += answer.choices
    .map((cs: any) => cs.map(Ciphertext.toString).join(","))
    .join(",");

  if (!IndividualProof.verify(
      election,
      S,
      [ answer.overall_proof ],
      eg,
      1,
      1,
    )) {
    throw new Error("Invalid overall proof");
  }

  if (!verifyNonZeroProof(election, ballot, question, answer)) {
    throw new Error("Invalid non zero proof");
  }

  if (!verifyListProofs(election, ballot, question, answer)) {
    throw new Error("Invalid list proof");
  }

  return true;
}

function verifyNonZeroProof(
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

  const A1 = ct.pAlpha.multiply(t1).add(Point.g.multiply(t2));
  const A2 = ct.pBeta.multiply(t1).add(pY.multiply(t2)).add(A0.multiply(c));

  let S = `${Election.fingerprint(election)}|${ballot.credential}|`;
  S += answer.choices
    .map((cs: any) => cs.map(Ciphertext.toString).join(","))
    .join(",");

  return Hnonzero(S, A0, A1, A2) === c;
}

function verifyListProofs(
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

    const [A0, B0] = Point.compute_commitment_pair(pY, ct0, proofs[0], 1);

    const A1 = Point.compute_commitment(Point.g, ct.pAlpha, proofs[1]);
    const B1 = Point.compute_commitment(pY, ct.pBeta, proofs[1]);

    let S = `${Election.fingerprint(election)}|${ballot.credential}|`;
    S += answer.choices
      .map((cs: any) => cs.map(Ciphertext.toString).join(","))
      .join(",");

    const challengeS = Z.modL(proofs[0].nChallenge + proofs[1].nChallenge);

    return (
      answer.choices[i].length === question.value.answers[i].length &&
      Hlproof(S, A0, B0, A1, B1) === challengeS
    );
  }
}
