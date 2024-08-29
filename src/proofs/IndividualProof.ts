import * as Election from "../Election";
import * as Proof from "../Proof";
import * as Point from "../Point";
import * as Ciphertext from "../Ciphertext";
import { L, mod, g, formula2, rand, formula, Hiprove, Hdecrypt } from "../math";

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

export function generate(
  election: Election.t,
  prefix: string,
  pAlpha: Point.t,
  pBeta: Point.t,
  r: bigint,
  m: number,
  M: Array<number>,
) {
  const pY = Point.parse(election.public_key);
  const w = rand();
  let commitments: Array<Point.t> = [];
  let proofs: Array<Proof.t> = [];

  for (let i = 0; i < M.length; i++) {
    if (m !== M[i]) {
      const nChallenge = rand();
      const nResponse = rand();
      proofs.push({ nChallenge, nResponse });
      const [pA, pB] = formula2(pY, pAlpha, pBeta, nChallenge, nResponse, M[i]);
      commitments.push(pA, pB);
    } else {
      // m === M[i]
      proofs.push({ nChallenge: BigInt(0), nResponse: BigInt(0) });
      const pA = g.multiply(w);
      const pB = pY.multiply(w);
      commitments.push(pA, pB);
    }
  }

  const S = `${Election.fingerprint(election)}|${prefix}`;
  const nH = Hiprove(S, pAlpha, pBeta, ...commitments);

  const nSumChallenge = proofs.reduce((acc, proof) => {
    return mod(acc + proof.nChallenge, L);
  }, BigInt(0));

  for (let i = 0; i < M.length; i++) {
    if (m === M[i]) {
      proofs[i].nChallenge = mod(nH - nSumChallenge, L);
      proofs[i].nResponse = mod(w - r * proofs[i].nChallenge, L);
    }
  }

  return proofs;
}
