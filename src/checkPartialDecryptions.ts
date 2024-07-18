import * as Ciphertext from "./ciphertext";
import * as Proof from "./proof";
import * as Point from "./point";
import * as Question from "./question";
import { rev, g, L, mod, formula, parsePoint, Hdecrypt } from "./math";
import sjcl from "sjcl";

export default function (state) {
  const election = state.setup.payload.election;
  const encrypted_tally = state.encryptedTally.payload.encrypted_tally;

  for (let n = 0; n < state.partialDecryptions.length; n++) {
    const partialDecryption = state.partialDecryptions[n];
    const { decryption_factors, decryption_proofs } =
      partialDecryption.payload.payload;
    const pPublicKey = getPublicKey(state, n);

    for (let i = 0; i < election.questions.length; i++) {
      const question = election.questions[i];
      if (Question.IsQuestionH(question)) {
        for (let j = 0; j < encrypted_tally[i].length; j++) {
          if (
            !Proof.checkDecryptionProof(
              `${state.electionFingerprint}|${Point.serialize(pPublicKey)}`,
              pPublicKey,
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
          for (let k = 0; k < encrypted_tally[i][j].length; k++) {
            if (
              !Proof.checkDecryptionProof(
                `${state.electionFingerprint}|${Point.serialize(pPublicKey)}`,
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
}

function getPublicKey(state, n) {
  const partialDecryption = state.partialDecryptions[n];
  let nKey = 0;
  for (let i = 0; i < state.setup.payload.trustees.length; i++) {
    if (state.setup.payload.trustees[i][0] == "Single") {
      if (nKey === partialDecryption.payload.owner - 1) {
        return parsePoint(state.setup.payload.trustees[i][1].public_key);
      }
      nKey++;
    } else {
      // Pedersen
      for (
        let j = 0;
        j < state.setup.payload.trustees[i][1].verification_keys.length;
        j++
      ) {
        if (nKey === partialDecryption.payload.owner - 1) {
          return parsePoint(state.setup.payload.trustees[i][1]
                            .verification_keys[j].public_key);
        }
        nKey++;
      }
    }
  }

  return null;
}
