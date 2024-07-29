import * as Event from "./Event";
import * as Ciphertext from "./Ciphertext";
import * as Proof from "./Proof";
import * as Point from "./Point";
import * as Question from "./Question";

export type t = {
  owner: number;
  payload: {
    decryption_factors: Array<Array<Point.Serialized.t>>;
    decryption_proofs: Array<Array<Proof.Serialized.t>>;
  };
};

export function verify(state: any, partialDecryption: Event.t<t>) {
  const election = state.setup.payload.election;
  const encrypted_tally = state.encryptedTally.payload.encrypted_tally;
  const { decryption_factors, decryption_proofs } =
    partialDecryption.payload.payload;
  const pPublicKey = getPublicKey(state, partialDecryption.payload.owner - 1);

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

function getPublicKey(state, ownerIndex) {
  let nKey = 0;
  for (let i = 0; i < state.setup.payload.trustees.length; i++) {
    if (state.setup.payload.trustees[i][0] == "Single") {
      if (nKey === ownerIndex) {
        return Point.parse(state.setup.payload.trustees[i][1].public_key);
      }
      nKey++;
    } else {
      // Pedersen
      for (
        let j = 0;
        j < state.setup.payload.trustees[i][1].verification_keys.length;
        j++
      ) {
        if (nKey === ownerIndex) {
          return Point.parse(state.setup.payload.trustees[i][1]
                            .verification_keys[j].public_key);
        }
        nKey++;
      }
    }
  }

  return null;
}
