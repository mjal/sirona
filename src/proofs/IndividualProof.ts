import * as Election from "../Election";
import * as Proof from "../Proof";
import * as Point from "../Point";
import * as Ciphertext from "../Ciphertext";
import { L, mod, formula2, formula, Hiprove, Hdecrypt } from "../math";

export function verify(
  election: Election.t,
  prefix: string,
  proof: Array<Proof.t>,
  eCiphertext: Ciphertext.t,
  min: number,
  max: number,
) {
  const pY = Point.parse(election.public_key);
  const S = `${Election.fingerprint(election)}|${prefix}`;
  const nSumChallenges = proof.reduce(
    (acc: bigint, proof: Proof.t) => mod(acc + proof.nChallenge, L),
    0n,
  );

  let commitments = [];
  for (let j = 0; j <= max - min; j++) {
    const [pA, pB] = formula2(
      pY,
      eCiphertext.pAlpha,
      eCiphertext.pBeta,
      proof[j].nChallenge,
      proof[j].nResponse,
      min + j,
    );
    commitments.push(pA, pB);
  }

  return Hiprove(S, eCiphertext.pAlpha, eCiphertext.pBeta, ...commitments) === nSumChallenges;
}

