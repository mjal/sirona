import * as Election from "../Election";
import * as Proof from "../Proof";
import * as Point from "../Point";
import * as Ciphertext from "../Ciphertext";
import * as Z from "../Z";
import { H } from "../math"

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
    const [A, B] = Point.compute_commitment_pair(pY, eg, proof[j], min + j);
    commitments.push(A, B);
  }

  return H_iprove(S, eg, ...commitments) === challengeS;
}

export function generate(
  election: Election.t,
  prefix: string,
  eg: Ciphertext.t,
  r: bigint,
  m: number,
  M: Array<number>, // NOTE: Could be replaced by max and min
) {
  const y = Point.parse(election.public_key);
  const w = Z.randL();

  let commitments: Array<Point.t> = [];
  let proof: Array<Proof.t> = [];
  for (let i = 0; i < M.length; i++) {
    const z = m === M[i] ? Proof.zero() : Proof.rand();
    const [A, B] =
      m === M[i]
        ? [Point.g.multiply(w), y.multiply(w)]
        : Point.compute_commitment_pair(y, eg, z, M[i]);
    proof.push(z);
    commitments.push(A, B);
  }

  const S = `${Election.fingerprint(election)}|${prefix}`;
  const h = H_iprove(S, eg, ...commitments);
  const challengeS = Z.sumL(proof.map(({ nChallenge }) => nChallenge));

  for (let i = 0; i < M.length; i++) {
    if (m === M[i]) {
      proof[i].nChallenge = Z.modL(h - challengeS);
      proof[i].nResponse = Z.modL(w - r * proof[i].nChallenge);
    }
  }

  return proof;
}

function H_iprove(S: string, eg: Ciphertext.t, ...commitments: Array<Point.t>) {
  const prefix = `prove|${S}|${Ciphertext.serialize(eg)}}`;
  return H(prefix, ...commitments);
}

