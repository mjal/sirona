import * as Point from "./Point";

export type t = {
  pCommitment: Point.t;
  nChallenge: bigint;
  nResponse: [bigint, bigint];
};

export type serialized_t = {
  commitment: string;
  challenge: string;
  response: [string, string];
};

export function serialize(proof: t): serialized_t {
  return {
    commitment: Point.serialize(proof.pCommitment),
    challenge: proof.nChallenge.toString(),
    response: [proof.nResponse[0].toString(), proof.nResponse[1].toString()],
  };
}

export function parse(proof: serialized_t): t {
  return {
    pCommitment: Point.parse(proof.commitment),
    nChallenge: BigInt(proof.challenge),
    nResponse: [BigInt(proof.response[0]), BigInt(proof.response[1])],
  };
}
