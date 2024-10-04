import * as Proof from "../Proof";
import * as Point from "../Point";
import * as Zq from "../Zq";
import H from "../H";

export function verify(hash: string, public_key: Point.t, proof: Proof.t) {
  const A = Point.commit(Point.g, public_key, proof);

  return H_signature(hash, A) === proof.challenge;
}

export function generate(hash: string, private_key: bigint) {
  const w = Zq.rand();
  const A = Point.g.multiply(w);

  const challenge = H_signature(hash, A);
  const response = Zq.mod(w - private_key * challenge);

  return { challenge, response };
}

function H_signature(S: string, A: Point.t) {
  return H(`sig|${S}`, A);
}
