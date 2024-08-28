import * as Setup from "./Setup";
import * as Election from "./Election";
import * as Ciphertext from "./Ciphertext";
import * as EncryptedTally from "./EncryptedTally";
import * as Proof from "./Proof";
import * as Point from "./Point";
import * as Trustee from "./Trustee";
import * as Question from "./Question";

export type t = {
  owner: number;
  payload: {
    decryption_factors: Array<Array<Point.Serialized.t>>;
    decryption_proofs: Array<Array<Proof.Serialized.t>>;
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
          !Proof.verifyDecryptionProof(
            `${Election.fingerprint(election)}|${Point.serialize(pPublicKey)}`,
            pPublicKey, // @ts-ignore
            Ciphertext.parse(encrypted_tally[i][j]),
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
            !Proof.verifyDecryptionProof(
              `${Election.fingerprint(election)}|${Point.serialize(pPublicKey)}`,
              pPublicKey,
              Ciphertext.parse(encrypted_tally[i][j][k]),
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
