import * as Zq from "./Zq";

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
