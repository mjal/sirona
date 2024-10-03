import { map2, range } from "./utils";
import * as Proof from "./Proof";
import * as IndividualProof from "./proofs/IndividualProof";
import * as BlankProof from "./proofs/BlankProof";
import * as ElGamal from "./ElGamal";
import * as Election from "./Election";
import * as Question from "./Question";
import * as Ballot from "./Ballot";
import * as Credential from "./Credential";
import * as Zq from "./Zq";

export type t = {
  choices: ElGamal.t[];
  individual_proofs: Proof.t[][];
  overall_proof: Proof.t[];
  blank_proof?: Proof.t[];
};

export type serialized_t = {
  choices: ElGamal.serialized_t[];
  individual_proofs: Proof.serialized_t[][];
  overall_proof: Proof.serialized_t[];
  blank_proof?: Proof.serialized_t[];
};

export function parse(answer: serialized_t): t {
  let obj: t = {
    choices: answer.choices.map(ElGamal.parse),
    individual_proofs: map2(answer.individual_proofs, Proof.parse),
    overall_proof: answer.overall_proof.map(Proof.parse),
  };
  if (answer.blank_proof) {
    obj.blank_proof = answer.blank_proof.map(Proof.parse);
  }
  return obj;
}

export function serialize(answer: t): serialized_t {
  let obj: serialized_t = {
    choices: answer.choices.map(ElGamal.serialize),
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
  serializedAnswer: serialized_t,
): boolean {
  const answer = parse(serializedAnswer);

  for (let j = 0; j < question.answers.length; j++) {
    if (ElGamal.isValid(answer.choices[j]) === false) {
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
        0,
        1,
      )
    ) {
      throw new Error("Invalid individual proofs");
    }
  }

  if (question.blank) {
    if (!BlankProof.BlankProof.verify(election, ballot.credential, answer)) {
      throw new Error("Invalid blank proof");
    }
    if (
      !BlankProof.OverallProof.verify(
        election,
        ballot.credential,
        question,
        answer,
      )
    ) {
      throw new Error("Invalid overall proof");
    }
  } else {
    const eg = ElGamal.combine(answer.choices);
    let suffix = answer.choices.map(ElGamal.toString).join(",");
    if (
      !IndividualProof.verify(
        election,
        ballot.credential + "|" + suffix,
        answer.overall_proof,
        eg,
        question.min,
        question.max,
      )
    ) {
      throw new Error("Invalid overall proof");
    }
  }

  return true;
}

export function generate(
  election: Election.t,
  question: Question.QuestionH.t,
  seed: string,
  plaintexts: number[],
): serialized_t {
  const y = election.public_key;
  const { hPublicCredential } = Credential.derive(election.uuid, seed);

  let nonces: bigint[] = [];
  let ciphertexts: ElGamal.t[] = [];
  let individual_proofs: Proof.t[][] = [];
  for (let i = 0; i < plaintexts.length; i++) {
    const r = Zq.rand();
    const { alpha, beta } = ElGamal.encrypt(y, r, plaintexts[i]);
    const proof = IndividualProof.generate(
      election,
      hPublicCredential,
      { alpha, beta },
      r,
      plaintexts[i],
      [0, 1],
    );
    ciphertexts.push({ alpha, beta });
    individual_proofs.push(proof);
    nonces.push(r);
  }

  if (question.blank) {
    const isBlank = plaintexts[0] === 1;
    const egS = ElGamal.combine(ciphertexts.slice(1));
    const eg0 = ciphertexts[0];
    const nRS = Zq.sum(nonces.slice(1));
    const nR0 = nonces[0];

    return serialize({
      choices: ciphertexts,
      individual_proofs,
      overall_proof: BlankProof.OverallProof.generate(
        election,
        hPublicCredential,
        question,
        plaintexts,
        ciphertexts,
        nonces,
      ),
      blank_proof: BlankProof.BlankProof.generate(
        election,
        hPublicCredential,
        ciphertexts,
        isBlank ? eg0 : egS,
        isBlank ? nRS : nR0,
        isBlank,
      ),
    });
  } else {
    const egS = ElGamal.combine(ciphertexts);
    const m = plaintexts.reduce((acc, c) => c + acc, 0);
    const M = range(question.min, question.max);
    const nR = Zq.sum(nonces);
    let prefix =
      hPublicCredential + "|" + ciphertexts.map(ElGamal.toString).join(",");
    const overall_proof = IndividualProof.generate(
      election,
      prefix,
      egS,
      nR,
      m,
      M,
    );

    return serialize({
      choices: ciphertexts,
      individual_proofs,
      overall_proof,
    });
  }
}
