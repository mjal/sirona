import * as Proof from "./Proof";
import * as Ciphertext from "./Ciphertext";
import * as Point from "./Point";
import * as Z from "./Z";
import { Hdecrypt } from "./math";

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

export function zero() {
  return {
    nChallenge: 0n,
    nResponse: 0n,
  };
}

export function rand() {
  return {
    nChallenge: Z.randL(),
    nResponse: Z.randL(),
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
  const A = Point.compute_commitment(Point.g, y, proof);
  const B = Point.compute_commitment(e.pAlpha, factor, proof);
  return Hdecrypt(S, A, B) === proof.nChallenge;
}
