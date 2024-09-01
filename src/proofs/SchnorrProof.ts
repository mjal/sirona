import * as Proof from "../Proof";
import * as Question from "../Question";
import * as AnswerH from "../AnswerH";
import * as Election from "../Election";
import * as Point from "../Point";
import * as Ciphertext from "../Ciphertext";
import * as Z from "../Z";
import { Hbproof0, Hbproof1 } from "../math";
import { range } from "../utils";
import { Hsignature } from "../math";

export function verify(
  hash: string,
  public_key: Point.t,
  proof: Proof.t) {

  const A = Point.compute_commitment(Point.g, public_key, proof);
  return (Hsignature(hash, A) === proof.nChallenge);
}


