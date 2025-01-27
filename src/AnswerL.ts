import { map2, map3 } from "./utils";
import * as Zq from "./Zq";
import * as Proof from "./Proof";
import * as IndividualProof from "./proofs/IndividualProof";
import * as NonZeroProof from "./ProofNonZero";
import * as ElGamal from "./ElGamal";
import * as Election from "./Election";
import * as Question from "./Question";
import * as Ballot from "./Ballot";
import * as Point from "./Point";
import { Hlproof, Hnonzero } from "./math";

export type t = {
  choices: ElGamal.t[][];
  individual_proofs: Proof.t[][][];
  overall_proof: Proof.t;
  list_proofs: Proof.t[];
  nonzero_proof: NonZeroProof.t;
};

export type serialized_t = {
  choices: ElGamal.serialized_t[][];
  individual_proofs: Proof.serialized_t[][][];
  overall_proof: Proof.serialized_t;
  list_proofs: Proof.serialized_t[][];
  nonzero_proof: NonZeroProof.serialized_t;
};

export function parse(answer: serialized_t): t {
  return {
    choices: map2(answer.choices, ElGamal.parse),
    individual_proofs: map3(answer.individual_proofs, Proof.parse),
    overall_proof: Proof.parse(answer.overall_proof),
    list_proofs: map2(answer.list_proofs, Proof.parse),
    nonzero_proof: NonZeroProof.parse(answer.nonzero_proof),
  };
}

export function serialize(answer: t): serialized_t {
  return {
    choices: map2(answer.choices, ElGamal.serialize),
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
  serializedAnswer: serialized_t,
): boolean {
  const answer = parse(serializedAnswer);

  for (let i = 0; i < question.value.answers.length; i++) {
    for (let j = 0; j < question.value.answers[i].length; j++) {
      if (ElGamal.isValid(answer.choices[i][j]) === false) {
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

  const eg = ElGamal.combine(answer.choices.map((c) => c[0]));
  let S = `${ballot.credential}|`;
  S += answer.choices
    .map((cs: any) => cs.map(ElGamal.toString).join(","))
    .join(",");

  if (!IndividualProof.verify(election, S, [answer.overall_proof], eg, 1, 1)) {
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
  const y = election.public_key;

  const ct = ElGamal.combine(
    answer.choices.map((choices) => {
      return ElGamal.combine(choices.slice(1));
    }),
  );

  const A0 = answer.nonzero_proof.commitment;
  const c = answer.nonzero_proof.challenge;
  const [t1, t2] = answer.nonzero_proof.response;

  if (Point.isEqual(A0, Point.zero)) {
    return false;
  }

  const A1 = ct.alpha.multiply(t1).add(Point.g.multiply(t2));
  const A2 = ct.beta.multiply(t1).add(y.multiply(t2)).add(A0.multiply(c));

  let S = `${Election.fingerprint(election)}|${ballot.credential}|`;
  S += answer.choices
    .map((cs: any) => cs.map(ElGamal.toString).join(","))
    .join(",");

  return Hnonzero(S, A0, A1, A2) === c;
}

function verifyListProofs(
  election: Election.t,
  ballot: Ballot.t,
  question: Question.QuestionL.t,
  answer: t,
): boolean {
  const y = election.public_key;

  for (let i = 0; i < question.value.answers.length; i++) {
    const proofs = answer.list_proofs[i];
    const ct0 = answer.choices[i][0];
    const ct = ElGamal.combine(answer.choices[i].slice(1));

    const [A0, B0] = Point.commit_pair(y, ct0, proofs[0], 1);

    const A1 = Point.commit(Point.g, ct.alpha, proofs[1]);
    const B1 = Point.commit(y, ct.beta, proofs[1]);

    let S = `${Election.fingerprint(election)}|${ballot.credential}|`;
    S += answer.choices
      .map((cs: any) => cs.map(ElGamal.toString).join(","))
      .join(",");

    const challengeS = Zq.mod(proofs[0].challenge + proofs[1].challenge);

    return (
      answer.choices[i].length === question.value.answers[i].length &&
      Hlproof(S, A0, B0, A1, B1) === challengeS
    );
  }
}
