import * as Election from "../Election";
import * as Proof from "../Proof";
import * as Point from "../Point";
import * as Ciphertext from "../Ciphertext";
import * as Z from "../Z";
import { Hiprove } from "../math";

export function verify(
  election: Election.t,
  prefix: string,
  proof: Array<Proof.t>,
  eg: Ciphertext.t,
  min: number,
  max: number,
) {
  const pY = Point.parse(election.public_key);
  const S = `${Election.fingerprint(election)}|${prefix}`;
  const challengeS = Z.sumL(proof.map(({ nChallenge }) => nChallenge));

  let commitments = [];
  for (let j = 0; j <= max - min; j++) {
    const [A, B] = Point.compute_commitment_pair(
      pY,
      eg,
      proof[j],
      min + j,
    );
    commitments.push(A, B);
  }

  return Hiprove(S, eg.pAlpha, eg.pBeta, ...commitments) === challengeS;
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
  const w = Z.randL();
  let commitments: Array<Point.t> = [];
  let proof: Array<Proof.t> = [];

  for (let i = 0; i < M.length; i++) {
    if (m !== M[i]) {
      const z = Proof.rand();
      const [A, B] = Point.compute_commitment_pair(y, eg, z, M[i]);
      proof.push(z);
      commitments.push(A, B);
    } else {
      const z = { nChallenge: 0n, nResponse: 0n };
      const [A, B] = [ Point.g.multiply(w), y.multiply(w) ];
      proof.push(z);
      commitments.push(A, B);
    }
  }

  const S = `${Election.fingerprint(election)}|${prefix}`;
  const nH = Hiprove(S, eg.pAlpha, eg.pBeta, ...commitments);
  const challengeS = Z.sumL(proof.map(({ nChallenge }) => nChallenge));

  for (let i = 0; i < M.length; i++) {
    if (m === M[i]) {
      proof[i].nChallenge = Z.modL(nH - challengeS);
      proof[i].nResponse = Z.modL(w - r * proof[i].nChallenge);
    }
  }

  return proof;
}
