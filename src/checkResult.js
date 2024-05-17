import { ed25519 } from "@noble/curves/ed25519";
import { check } from "./utils.js";
import { g, rev, one } from "./math";

export default function (state) {
  const et = state.encryptedTally.payload.encrypted_tally;
  const res = state.result.payload.result;
  for (let i = 0; i < res.length; i++) {
    const question = state.setup.payload.election.questions[i];
    if (question.type === "NonHomomorphic") {
      continue; // TODO
    }
    for (let j = 0; j < res[i].length; j++) {
      let pSum = one;
      for (let k = 0; k < state.partialDecryptions.length; k++) {
        const partialDecryption = state.partialDecryptions[k];
        const df = partialDecryption.payload.payload.decryption_factors;
        const pFactor = parsePoint(df[i][j]);
        pSum = pSum.add(pFactor);
      }

      const pBeta = parsePoint(et[i][j].beta);
      const pResult = pBeta.add(pSum.negate());
      const nAnswer = BigInt(res[i][j]);

      check(
        "result",
        `Result ${i},${j} correspond to the log of the sum of partial decryptions`,
        (res[i][j] === 0 && pResult.toHex() === one.toHex()) ||
          (res[i][j] !== 0 && pResult.toHex() === g.multiply(nAnswer).toHex()),
      );
    }
  }
}
