export type Proof = {
  challenge: string;
  response: string
};

export type Ciphertext = {
  alpha: string;
  beta: string
};

export type AnswerH = {
  choices: Array<Ciphertext>;
  individual_proofs: Array<Array<Proof>>;
  overall_proof: Array<Proof>;
  blank_proof?: [Proof, Proof];
};

export type AnswerNH = {
  choices: Ciphertext;
  proof: Proof;
};

export type AnswerL = {
  choices: Array<Array<Ciphertext>>;
  proof: Proof;
  individual_proofs: Array<Array<Array<Proof>>>;
  overall_proof: Array<Proof>;
  list_proofs: Array<Proof>;
  //nonzero_proof: Array<tSerializedNonZeroProof>;
};


