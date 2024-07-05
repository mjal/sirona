import * as Proof from './proof';
import * as Ciphertext from './ciphertext';
import * as Point from './point';
import {
  L,
  mod,
  formula2,
  Hiprove,
} from "./math";

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

export function checkIndividualProof(
  S: string,
  zIndividualProof: Array<Proof.t>,
  pY: Point.t,
  eCiphertext: Ciphertext.t,
) {
  const nSumChallenges = mod(zIndividualProof[0].nChallenge + zIndividualProof[1].nChallenge, L);
  const [pA0, pB0] = formula2(
    pY,
    eCiphertext.pAlpha,
    eCiphertext.pBeta,
    zIndividualProof[0].nChallenge,
    zIndividualProof[0].nResponse,
    0,
  );
  const [pA1, pB1] = formula2(
    pY,
    eCiphertext.pAlpha,
    eCiphertext.pBeta,
    zIndividualProof[1].nChallenge,
    zIndividualProof[1].nResponse,
    1,
  );
  const nH = Hiprove(S, eCiphertext.pAlpha, eCiphertext.pBeta, pA0, pB0, pA1, pB1);
  return nSumChallenges === nH;
}
