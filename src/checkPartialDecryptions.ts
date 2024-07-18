import * as Ciphertext from "./ciphertext";
import * as Proof from "./proof";
import * as Point from "./point";
import * as Question from "./question";
import { rev, g, L, mod, formula, parsePoint, Hdecrypt } from "./math";
import sjcl from "sjcl";

export default function (state) {
  const et = state.encryptedTally.payload.encrypted_tally;

  for (let k = 0; k < state.partialDecryptions.length; k++) {
    const partialDecryption = state.partialDecryptions[k];

    let nKey = 0;
    let pPublicKey = null;
    for (let i = 0; i < state.setup.payload.trustees.length; i++) {
      if (state.setup.payload.trustees[i][0] == "Single") {
        if (nKey === partialDecryption.payload.owner - 1) {
          pPublicKey = state.setup.payload.trustees[i][1].public_key;
          break;
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
            pPublicKey =
              state.setup.payload.trustees[i][1].verification_keys[j]
                .public_key;
          }
          nKey++;
        }
        if (nKey > partialDecryption.payload.owner - 1) {
          break;
        }
      }
    }
    pPublicKey = parsePoint(pPublicKey);
    const df = partialDecryption.payload.payload.decryption_factors;
    const dp = partialDecryption.payload.payload.decryption_proofs;

    for (let i = 0; i < et.length; i++) {
      const question = state.setup.payload.election.questions[i];
      if (Question.IsQuestionH(question)) {
        for (let j = 0; j < et[i].length; j++) {
          if (!Proof.checkDecryptionProof(
            `${state.electionFingerprint}|${Point.serialize(pPublicKey)}`,
            pPublicKey,
            Ciphertext.parse(et[i][j]),
            Point.parse(df[i][j]),
            Proof.parse(dp[i][j])
          )) {
            throw new Error("Invalid decryption proof");
          }
        }
      } else {
        continue; // TODO
      }
    }
  }
}
