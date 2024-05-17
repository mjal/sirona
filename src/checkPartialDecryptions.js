import { assert, check } from "./utils.js";
import { rev, g, L, mod, parsePoint } from "./math";
import sjcl from "sjcl";

export default function (state) {
  const et = state.encryptedTally.payload.encrypted_tally;

  for (let k = 0; k < state.partialDecryptions.length; k++) {
    const partialDecryption = state.partialDecryptions[k];
    const trusteeIdx = partialDecryption.payload.owner - 1;
    assert(state.setup.payload.trustees[trusteeIdx][0] === "Single");
    const pPublicKey = parsePoint(
      state.setup.payload.trustees[trusteeIdx][1].public_key,
    );
    const df = partialDecryption.payload.payload.decryption_factors;
    const dp = partialDecryption.payload.payload.decryption_proofs;

    for (let i = 0; i < et.length; i++) {
      const question = state.setup.payload.election.questions[i];
      if (question.type === "NonHomomorphic") {
        continue; // TODO
      }
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
        );
      }
    }
  }

  // TODO: Check that there is a partial decryption for every trustee
  // (Maybe in checkResult)
}
