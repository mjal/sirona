import { rev, parsePoint } from "./math";
import type { ExtPointType } from "@noble/curves/abstract/edwards.js";

export type Point = ExtPointType;
export type Proof = { nChallenge: bigint; nResponse: bigint };
export type Ciphertext = { pAlpha: Point; pBeta: Point };

import * as Serialized from "./serialized";
export { Serialized };

export type AnswerH = {
  aeChoices: Array<Ciphertext>;
  aazIndividualProofs: Array<Array<Proof>>;
  azOverallProof: Array<Proof>;
  azBlankProof?: [Proof, Proof];
};

export function serializeProof(proof: Proof): Serialized.Proof {
  return {
    challenge: proof.nChallenge.toString(),
    response: proof.nResponse.toString(),
  };
}

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

export function parseProof(proof: Serialized.Proof): Proof {
  return {
    nChallenge: BigInt(proof.challenge),
    nResponse: BigInt(proof.response),
  };
}

function parseAnswerH(answer: Serialized.AnswerH) : AnswerH {
  let obj : AnswerH = {
    aeChoices: answer.choices.map(parseCiphertext),
    aazIndividualProofs: answer.individual_proofs.map((proofs) =>
      proofs.map(parseProof)
    ),
    azOverallProof: answer.overall_proof.map(parseProof),
  };
  if (answer.blank_proof) {
    obj.azBlankProof = [
      parseProof(answer.blank_proof[0]),
      parseProof(answer.blank_proof[1])
    ];
  }
  return obj;
}

export function IsAnswerH(answer: any, question: any) : answer is Serialized.AnswerH {
  return (question.type === undefined);
}

export function IsAnswerNH(answer: any, question: any) : answer is Serialized.AnswerNH {
  return (question.type === "NonHomomorphic");
}

export function IsAnswerL(answer: any, question: any) : answer is Serialized.AnswerL {
  return (question.type === "Lists");
}
