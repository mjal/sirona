import { ed25519 } from "@noble/curves/ed25519";
import { check } from "./utils.js";
import { g, rev, one } from "./math.js";

export default function (state) {
  const et = state.encryptedTally.payload.encrypted_tally;
  const res = state.result.payload.result;
  for (let i = 0; i < res.length; i++) {
    for (let j = 0; j < res[i].length; j++) {
      let sum = one;
      for (let k = 0; k < state.partialDecryptions.length; k++) {
        const partialDecryption = state.partialDecryptions[k];
        const df = partialDecryption.payload.payload.decryption_factors;
        const factor = ed25519.ExtendedPoint.fromHex(rev(df[i][j]));
        sum = sum.add(factor);
      }

      const beta = ed25519.ExtendedPoint.fromHex(rev(et[i][j].beta));
      const result = beta.add(sum.negate());

      check(
        "result",
        `Result ${i},${j} correspond to the log of the sum of partial decryptions`,
        (res[i][j] === 0 && result.toHex() === one.toHex()) ||
          (res[i][j] !== 0 &&
            result.toHex() === g.multiply(BigInt(res[i][j])).toHex()),
      );
    }
  }
}
