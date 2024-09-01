import * as Proof from "../Proof";
import * as Point from "../Point";
import * as Z from "../Z";
import H from "../H";

export function verify(hash: string, public_key: Point.t, proof: Proof.t) {
  const A = Point.compute_commitment(Point.g, public_key, proof);

  return H_signature(hash, A) === proof.nChallenge;
}

export function generate(hash: string, private_key: bigint) {
  const w = Z.randL();
  const A = Point.g.multiply(w);

  const nChallenge = H_signature(hash, A);
  const nResponse = Z.modL(w - private_key * nChallenge);

  return { nChallenge, nResponse };
}

function H_signature(S: string, A: Point.t) {
  return H(`sig|${S}`, A);
}
