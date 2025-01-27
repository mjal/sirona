import * as Setup from "./Setup";
import * as Election from "./Election";
import * as ElGamal from "./ElGamal";
import * as EncryptedTally from "./EncryptedTally";
import * as Proof from "./Proof";
import * as Point from "./Point";
import * as Trustee from "./Trustee";
import * as Question from "./Question";
import * as DecryptionProof from "./proofs/DecryptionProof";

export type t = {
  owner: number;
  payload: {
    decryption_factors: Point.serialized_t[][];
    decryption_proofs: Proof.serialized_t[][];
  };
};

export function verify(
  partialDecryption: t,
  setup: Setup.t,
  encryptedTally: EncryptedTally.t,
) {
  const election = setup.election;
  const encrypted_tally = encryptedTally.encrypted_tally;
  const { decryption_factors, decryption_proofs } = partialDecryption.payload;
  const pPublicKey = Trustee.getPublicKeyByOwnerIndex(
    setup.trustees,
    partialDecryption.owner - 1,
  );

  for (let i = 0; i < election.questions.length; i++) {
    const question = election.questions[i];
    if (Question.IsQuestionH(question)) {
      for (let j = 0; j < encrypted_tally[i].length; j++) {
        if (
          !DecryptionProof.verify(
            `${Election.fingerprint(election)}|${Point.serialize(pPublicKey)}`,
            pPublicKey, // @ts-ignore
            ElGamal.parse(encrypted_tally[i][j]),
            Point.parse(decryption_factors[i][j]),
            Proof.parse(decryption_proofs[i][j]),
          )
        ) {
          throw new Error("Invalid decryption proof");
        }
      }
    } else if (
      Question.IsQuestionL(question) ||
      Question.IsQuestionNH(question)
    ) {
      for (let j = 0; j < encrypted_tally[i].length; j++) {
        // @ts-ignore
        for (let k = 0; k < encrypted_tally[i][j].length; k++) {
          if (
            !DecryptionProof.verify(
              `${Election.fingerprint(election)}|${Point.serialize(pPublicKey)}`,
              pPublicKey,
              ElGamal.parse(encrypted_tally[i][j][k]),
              Point.parse(decryption_factors[i][j][k]),
              Proof.parse(decryption_proofs[i][j][k]),
            )
          ) {
            throw new Error("Invalid decryption proof");
          }
        }
      }
    } else {
      throw new Error("Invalid question type");
    }
  }
}

export function generate(
  setup: Setup.t,
  encryptedTally: EncryptedTally.t,
  owner: number,
  x: bigint,
) : t {
  const election = setup.election;
  const encrypted_tally = encryptedTally.encrypted_tally;
  const X = Point.g.multiply(x);

  const decryption_factors : Point.serialized_t[][] = [];
  const decryption_proofs  : Proof.serialized_t[][] = [];

  for (let i = 0; i < election.questions.length; i++) {
    const question = election.questions[i];
    if (Question.IsQuestionH(question)) {
      const df = [], dp = [];
      for (let j = 0; j < encrypted_tally[i].length; j++) {
        // @ts-ignore
        const factor = Point.serialize(encrypted_tally[i][j].alpha.multiply(x))
        const proof = DecryptionProof.generate(
          `${Election.fingerprint(election)}|${Point.serialize(X)}`,
          // @ts-ignore
          encrypted_tally[i][j],
          x);
        df.push(factor);
        dp.push(Proof.serialize(proof));
      }
      decryption_factors.push(df);
      decryption_proofs.push(dp);
    } else if (
      Question.IsQuestionL(question) ||
      Question.IsQuestionNH(question)
    ) {
      throw new Error("TODO");
    } else {
      throw new Error("Invalid question type");
    }
  }

  return {
    owner,
    payload: {
      decryption_factors,
      decryption_proofs
    }
  };
}
