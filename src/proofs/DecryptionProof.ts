import { Hdecrypt } from "./../math";
import * as Proof from "./../Proof";
import * as ElGamal from "./../ElGamal";
import * as Point from "./../Point";
import * as Zq from "../Zq";

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

export function generate(
  S: string,
  e: ElGamal.t,
  x: bigint
) {
  const w = Zq.rand();
  const A = Point.g.multiply(w);
  const B = e.alpha.multiply(w);

  const challenge = Hdecrypt(S, A, B);
  const response = Zq.mod(w - x * challenge);

  return { challenge, response };
}
