import { assert, check } from "./utils.js";
import { rev, g, L, mod, parsePoint } from "./math";
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
      if (question.type === undefined) { // question_h
        for (let j = 0; j < et[i].length; j++) {
          const pAlpha = parsePoint(et[i][j].alpha);
          const pFactor = parsePoint(df[i][j]);
          const nChallenge = BigInt(dp[i][j].challenge);
          const nResponse = BigInt(dp[i][j].response);

          const pA = g.multiply(nResponse).add(pPublicKey.multiply(nChallenge));
          const pB = pAlpha.multiply(nResponse).add(pFactor.multiply(nChallenge));

          const hVerificationHash = sjcl.codec.hex.fromBits(
            sjcl.hash.sha256.hash(
              `decrypt|${state.setup.fingerprint}|${rev(pPublicKey.toHex())}|${rev(pA.toHex())},${rev(pB.toHex())}`,
            ),
          );
          const hReducedVerificationHash = mod(
            BigInt("0x" + hVerificationHash),
            L,
          ).toString(16);

          check(
            "partialDecryptions",
            "Valid decryption proof",
            nChallenge.toString(16) === hReducedVerificationHash,
            true,
          );
        }
      } else {
        continue; // TODO
      }
    }
  }

  // TODO: Check that there is a partial decryption for every trustee
  // (Maybe in checkResult)
}
