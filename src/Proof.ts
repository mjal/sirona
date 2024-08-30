import * as Proof from "./Proof";
import * as Ciphertext from "./Ciphertext";
import * as Point from "./Point";
import { formula, Hdecrypt } from "./math";

export type t = {
  nChallenge: bigint;
  nResponse: bigint;
};

export namespace Serialized {
  export type t = {
    challenge: string;
    response: string;
  };
}

export function serialize(proof: t): Serialized.t {
  return {
    challenge: proof.nChallenge.toString(),
    response: proof.nResponse.toString(),
  };
}

export function parse(proof: Serialized.t): t {
  return {
    nChallenge: BigInt(proof.challenge),
    nResponse: BigInt(proof.response),
  };
}

// TODO: Move to proofs/DecryptionProof.ts
export function verifyDecryptionProof(
  S: string,
  y: Point.t,
  e: Ciphertext.t,
  factor: Point.t,
  proof: Proof.t,
) {
  const pA = formula(Point.g, proof.nResponse, y, proof.nChallenge);
  const pB = formula(e.pAlpha, proof.nResponse, factor, proof.nChallenge);
  return Hdecrypt(S, pA, pB) === proof.nChallenge;
}
