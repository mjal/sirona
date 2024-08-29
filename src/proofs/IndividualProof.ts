import * as Election from "../Election";
import * as Proof from "../Proof";
import * as Point from "../Point";
import * as Ciphertext from "../Ciphertext";
import { L, mod, g, rand, Hiprove } from "../math";

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
    const [A, B] = Point.compute_commitment_pair(
      pY,
      eCiphertext,
      proof[j],
      min + j,
    );
    commitments.push(A, B);
  }

  return Hiprove(S, eCiphertext.pAlpha, eCiphertext.pBeta, ...commitments) === nSumChallenges;
}

export function generate(
  election: Election.t,
  prefix: string,
  eg: Ciphertext.t,
  r: bigint,
  m: number,
  M: Array<number>,
) {
  const y = Point.parse(election.public_key);
  const w = rand();
  let commitments: Array<Point.t> = [];
  let proofs: Array<Proof.t> = [];

  for (let i = 0; i < M.length; i++) {
    if (m !== M[i]) {
      const proof = { nChallenge: rand(), nResponse: rand() };
      const [A, B] = Point.compute_commitment_pair(y, eg, proof, M[i]);
      proofs.push(proof);
      commitments.push(A, B);
    } else {
      // m === M[i]
      proofs.push({ nChallenge: BigInt(0), nResponse: BigInt(0) });
      const pA = g.multiply(w);
      const pB = y.multiply(w);
      commitments.push(pA, pB);
    }
  }

  const S = `${Election.fingerprint(election)}|${prefix}`;
  const nH = Hiprove(S, eg.pAlpha, eg.pBeta, ...commitments);

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
