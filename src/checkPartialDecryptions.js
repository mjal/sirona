import { assert, check } from "./utils.js";
import { rev, one, g, l, erem } from "./math.js";
import { ed25519 } from "@noble/curves/ed25519";
import sjcl from "sjcl";

export default function (state) {
  const et = state.encryptedTally.payload.encrypted_tally;

  for (let k = 0; k < state.partialDecryptions.length; k++) {
    const partialDecryption = state.partialDecryptions[k];
    const trusteeIdx = partialDecryption.payload.owner - 1;
    assert(state.setup.payload.trustees[trusteeIdx][0] === "Single");
    const publicKey = ed25519.ExtendedPoint.fromHex(
      rev(state.setup.payload.trustees[trusteeIdx][1].public_key),
    );
    const df = partialDecryption.payload.payload.decryption_factors;
    const dp = partialDecryption.payload.payload.decryption_proofs;

    for (let i = 0; i < et.length; i++) {
      console.log(et[i]);
      const question = state.setup.payload.election.questions[i];
      if (question.type === "NonHomomorphic") {
        continue; // TODO
      }
      for (let j = 0; j < et[i].length; j++) {
        const alpha = ed25519.ExtendedPoint.fromHex(rev(et[i][j].alpha));
        const factor = ed25519.ExtendedPoint.fromHex(rev(df[i][j]));
        const challenge = BigInt(dp[i][j].challenge);
        const response = BigInt(dp[i][j].response);

        const A = g.multiply(response).add(publicKey.multiply(challenge));
        const B = alpha.multiply(response).add(factor.multiply(challenge));

        const verificationHash = sjcl.codec.hex.fromBits(
          sjcl.hash.sha256.hash(
            `decrypt|${state.setup.fingerprint}|${rev(publicKey.toHex())}|${rev(A.toHex())},${rev(B.toHex())}`,
          ),
        );
        const hexReducedVerificationHash = erem(
          BigInt("0x" + verificationHash),
          l,
        ).toString(16);

        check(
          "partialDecryptions",
          "Valid decryption proof",
          challenge.toString(16) === hexReducedVerificationHash,
        );
      }
    }
  }

  // TODO: Check that there is a partial decryption for every trustee
  // (Maybe in checkResult)
}
