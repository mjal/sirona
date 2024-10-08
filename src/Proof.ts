import * as Proof from "./Proof";
import * as ElGamal from "./ElGamal";
import * as Point from "./Point";
import * as Zq from "./Zq";
import { Hdecrypt } from "./math";

export type t = {
  nChallenge: bigint;
  nResponse: bigint;
};

export type serialized_t = {
  challenge: string;
  response: string;
};

export function serialize(proof: t): serialized_t {
  return {
    challenge: proof.nChallenge.toString(),
    response: proof.nResponse.toString(),
  };
}

export function parse(proof: serialized_t): t {
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
    nChallenge: Zq.rand(),
    nResponse: Zq.rand(),
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
  return Hdecrypt(S, A, B) === proof.nChallenge;
}
