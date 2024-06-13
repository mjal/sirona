import { rev, parsePoint } from "./math";
import type { ExtPointType } from "@noble/curves/abstract/edwards.js";
import * as Serialized from "./serialized";

// Serialized types
export { Serialized };

// Point
export type Point = ExtPointType;

// Proof
export type Proof = { nChallenge: bigint; nResponse: bigint };

export function serializeProof(proof: Proof): Serialized.Proof {
  return {
    challenge: proof.nChallenge.toString(),
    response: proof.nResponse.toString(),
  };
}

export function parseProof(proof: Serialized.Proof): Proof {
  return {
    nChallenge: BigInt(proof.challenge),
    nResponse: BigInt(proof.response),
  };
}

// Ciphertext
export type Ciphertext = { pAlpha: Point; pBeta: Point };

export function serializeCiphertext(c: Ciphertext): Serialized.Ciphertext {
  return {
    alpha: rev(c.pAlpha.toHex()),
    beta: rev(c.pBeta.toHex()),
  };
}

export function parseCiphertext(c: Serialized.Ciphertext): Ciphertext {
  return {
    pAlpha: parsePoint(c.alpha),
    pBeta: parsePoint(c.beta),
  };
}

// AnswerH
export type AnswerH = {
  aeChoices: Array<Ciphertext>;
  aazIndividualProofs: Array<Array<Proof>>;
  azOverallProof: Array<Proof>;
  azBlankProof?: Array<Proof>;
};

export function parseAnswerH(answer: Serialized.AnswerH) : AnswerH {
  let obj : AnswerH = {
    aeChoices: answer.choices.map(parseCiphertext),
    aazIndividualProofs: answer.individual_proofs.map((proofs) =>
      proofs.map(parseProof)
    ),
    azOverallProof: answer.overall_proof.map(parseProof),
  };
  if (answer.blank_proof) {
    obj.azBlankProof = answer.blank_proof.map(parseProof);
  }
  return obj;
}

export function serializeAnswerH(answer: AnswerH) : Serialized.AnswerH {
  let obj : Serialized.AnswerH = {
    choices: answer.aeChoices.map(serializeCiphertext),
    individual_proofs: answer.aazIndividualProofs.map((proofs) =>
      proofs.map(serializeProof)
    ),
    overall_proof: answer.azOverallProof.map(serializeProof),
  };
  if (answer.azBlankProof) {
    obj.blank_proof = answer.azBlankProof.map(serializeProof);
  }
  return obj;
}
