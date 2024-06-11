import type { ExtPointType } from "@noble/curves/abstract/edwards.js";
export type tPoint = ExtPointType;
export type tProof = { nChallenge: bigint; nResponse: bigint };
export type tSerializedProof = { challenge: string; response: string };
export type tCiphertext = { pAlpha: tPoint; pBeta: tPoint };
export type tSerializedCiphertext = { alpha: string; beta: string };
export type tAnswerWithoutBlank = {
  choices: Array<tSerializedCiphertext>;
  individual_proofs: Array<Array<tSerializedProof>>;
  overall_proof: Array<tSerializedProof>;
};
export type tAnswerWithBlank = {
  choices: Array<tSerializedCiphertext>;
  individual_proofs: Array<Array<tSerializedProof>>;
  blank_proof: Array<tSerializedProof>;
  overall_proof: Array<tSerializedProof>;
};
export type tAnswer = tAnswerWithoutBlank | tAnswerWithBlank;

