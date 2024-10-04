import * as Point from "./Point";

export type t = {
  // TODO: Rename to commitment
  pCommitment: Point.t;
  challenge: bigint;
  response: [bigint, bigint];
};

export type serialized_t = {
  commitment: string;
  challenge: string;
  response: [string, string];
};

export function serialize(proof: t): serialized_t {
  return {
    commitment: Point.serialize(proof.pCommitment),
    challenge: proof.challenge.toString(),
    response: [proof.response[0].toString(), proof.response[1].toString()],
  };
}

export function parse(proof: serialized_t): t {
  return {
    pCommitment: Point.parse(proof.commitment),
    challenge: BigInt(proof.challenge),
    response: [BigInt(proof.response[0]), BigInt(proof.response[1])],
  };
}
