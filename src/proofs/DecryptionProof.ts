import { Hdecrypt } from "./../math";
import * as Proof from "./../Proof";
import * as ElGamal from "./../ElGamal";
import * as Point from "./../Point";

export function verify(
  S: string,
  y: Point.t,
  e: ElGamal.t,
  factor: Point.t,
  proof: Proof.t,
) {
  const A = Point.commit(Point.g, y, proof);
  const B = Point.commit(e.alpha, factor, proof);
  return Hdecrypt(S, A, B) === proof.challenge;
}
