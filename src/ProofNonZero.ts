import * as Point from "./Point";

export type t = {
  commitment: Point.t;
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
    commitment: Point.serialize(proof.commitment),
    challenge: proof.challenge.toString(),
    response: [proof.response[0].toString(), proof.response[1].toString()],
  };
}

export function parse(proof: serialized_t): t {
  return {
    commitment: Point.parse(proof.commitment),
    challenge: BigInt(proof.challenge),
    response: [BigInt(proof.response[0]), BigInt(proof.response[1])],
  };
}
