export type t = {
  nChallenge: bigint;
  nResponse: bigint
};

export namespace Serialized {
  export type t = {
    challenge: string;
    response: string
  }
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
