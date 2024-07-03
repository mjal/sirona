import { map2, map3 } from './utils';
import * as Proof from './proof';
import * as NonZeroProof from './nonZeroProof';
import * as Ciphertext from './ciphertext';

export type t = {
  choices: Array<Array<Ciphertext.t>>;
  individual_proofs: Array<Array<Proof.t>>;
  overall_proof: Proof.t;
  list_proofs: Array<Proof.t>;
  nonzero_proof: NonZeroProof.t;
};

export namespace Serialized {
  export type t = {
    choices: Array<Array<Ciphertext.Serialized.t>>;
    individual_proofs: Array<Array<Array<Proof.Serialized.t>>>;
    overall_proof: Proof.Serialized.t;
    list_proofs: Array<Array<Proof.Serialized.t>>;
    nonzero_proof: NonZeroProof.Serialized.t;
  };
}

export function parse(answer: Serialized.t) : t {
  return {
    choices: map2(answer.choices, Ciphertext.parse),
    individual_proofs: map3(answer.individual_proofs, Proof.parse),
    overall_proof: Proof.parse(answer.overall_proof),
    list_proofs: map2(answer.list_proofs, Proof.parse),
    nonzero_proof: NonZeroProof.parse(answer.nonzero_proof)
  }
}
