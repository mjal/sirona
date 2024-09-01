import { map2, range } from "./utils";
import * as Proof from "./Proof";
import * as IndividualProof from "./proofs/IndividualProof";
import * as BlankProof from "./proofs/BlankProof";
import * as Ciphertext from "./Ciphertext";
import * as Election from "./Election";
import * as Question from "./Question";
import * as Ballot from "./Ballot";
import * as Point from "./Point";
import * as Credential from "./Credential";
import * as Z from "./Z";

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
    const eg = Ciphertext.combine(answer.choices);
    let suffix = answer.choices.map(Ciphertext.toString).join(",");
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
): Serialized.t {
  const y = Point.parse(election.public_key);
  const { hPublicCredential } = Credential.derive(election.uuid, seed);

  let nonces: Array<bigint> = [];
  let ciphertexts: Array<Ciphertext.t> = [];
  let individual_proofs: Array<Array<Proof.t>> = [];
  for (let i = 0; i < plaintexts.length; i++) {
    const r = Z.randL();
    const { pAlpha, pBeta } = Ciphertext.encrypt(y, r, plaintexts[i]);
    const proof = IndividualProof.generate(
      election,
      hPublicCredential,
      { pAlpha, pBeta },
      r,
      plaintexts[i],
      [0, 1],
    );
    ciphertexts.push({ pAlpha, pBeta });
    individual_proofs.push(proof);
    nonces.push(r);
  }

  if (question.blank) {
    const isBlank = plaintexts[0] === 1;
    const egS = Ciphertext.combine(ciphertexts.slice(1));
    const eg0 = ciphertexts[0];
    const nRS = Z.sumL(nonces.slice(1));
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
    const egS = Ciphertext.combine(ciphertexts);
    const m = plaintexts.reduce((acc, c) => c + acc, 0);
    const M = range(question.min, question.max);
    const nR = Z.sumL(nonces);
    let prefix =
      hPublicCredential + "|" + ciphertexts.map(Ciphertext.toString).join(",");
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
