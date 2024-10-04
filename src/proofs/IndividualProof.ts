import * as Election from "../Election";
import * as Proof from "../Proof";
import * as Point from "../Point";
import * as ElGamal from "../ElGamal";
import * as Zq from "../Zq";
import H from "../H";

export function verify(
  election: Election.t,
  prefix: string,
  proof: Array<Proof.t>,
  eg: ElGamal.t,
  min: number,
  max: number,
) {
  const y = election.public_key;
  const S = `${Election.fingerprint(election)}|${prefix}`;
  const challengeS = Zq.sum(proof.map(({ challenge }) => challenge));

  let commitments = [];
  for (let j = 0; j <= max - min; j++) {
    const [A, B] = Point.commit_pair(y, eg, proof[j], min + j);
    commitments.push(A, B);
  }

  return H_iprove(S, eg, ...commitments) === challengeS;
}

export function generate(
  election: Election.t,
  prefix: string,
  eg: ElGamal.t,
  r: bigint,
  m: number,
  M: Array<number>, // NOTE: Could be replaced by max and min
) {
  const y = election.public_key;
  const w = Zq.rand();

  let commitments: Array<Point.t> = [];
  let proof: Array<Proof.t> = [];
  for (let i = 0; i < M.length; i++) {
    const z = m === M[i] ? Proof.zero() : Proof.rand();
    const [A, B] =
      m === M[i]
        ? [Point.g.multiply(w), y.multiply(w)]
        : Point.commit_pair(y, eg, z, M[i]);
    proof.push(z);
    commitments.push(A, B);
  }

  const S = `${Election.fingerprint(election)}|${prefix}`;
  const h = H_iprove(S, eg, ...commitments);
  const challengeS = Zq.sum(proof.map(({ challenge }) => challenge));

  for (let i = 0; i < M.length; i++) {
    if (m === M[i]) {
      proof[i].challenge = Zq.mod(h - challengeS);
      proof[i].response = Zq.mod(w - r * proof[i].challenge);
    }
  }

  return proof;
}

function H_iprove(S: string, eg: ElGamal.t, ...commitments: Array<Point.t>) {
  const prefix = `prove|${S}|${ElGamal.toString(eg)}`;
  return H(prefix, ...commitments);
}
