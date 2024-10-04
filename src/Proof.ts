import * as Proof from "./Proof";
import * as ElGamal from "./ElGamal";
import * as Point from "./Point";
import * as Zq from "./Zq";
import { Hdecrypt } from "./math";

export type t = {
  challenge: bigint;
  response: bigint;
};

export type serialized_t = {
  challenge: string;
  response: string;
};

export function serialize(proof: t): serialized_t {
  return {
    challenge: proof.challenge.toString(),
    response: proof.response.toString(),
  };
}

export function parse(proof: serialized_t): t {
  return {
    challenge: BigInt(proof.challenge),
    response: BigInt(proof.response),
  };
}

export function zero() {
  return {
    challenge: 0n,
    response: 0n,
  };
}

export function rand() {
  return {
    challenge: Zq.rand(),
    response: Zq.rand(),
  };
}

// TODO: Move to proofs/DecryptionProof.ts
export function verifyDecryptionProof(
  S: string,
  y: Point.t,
  e: ElGamal.t,
  factor: Point.t,
  proof: Proof.t,
) {
  const A = Point.commit(Point.g, y, proof);
  const B = Point.commit(e.alpha, factor, proof);
  return Hdecrypt(S, A, B) === proof.challenge;
}
