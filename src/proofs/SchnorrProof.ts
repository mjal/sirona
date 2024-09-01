import * as Proof from "../Proof";
import * as Point from "../Point";
import * as Z from "../Z";
import { Hsignature } from "../math";

export function verify(
  hash: string,
  public_key: Point.t,
  proof: Proof.t) {
  const A = Point.compute_commitment(Point.g, public_key, proof);

  return (Hsignature(hash, A) === proof.nChallenge);
}

export function generate(hash: string, private_key: bigint) {
  const w = Z.randL();
  const A = Point.g.multiply(w);

  const nChallenge = Hsignature(hash, A);
  const nResponse = Z.mod(w - private_key * nChallenge, Z.L);

  return { nChallenge, nResponse };
}
