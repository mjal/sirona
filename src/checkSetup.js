import { check } from './utils.js';
import { g, l, rev, erem } from './math.js';
import { ed25519 } from '@noble/curves/ed25519';
import sjcl from "sjcl";

export default function(state) {
  // TODO: Handle more than one trustee
  // TODO: Handle pedersen trustees
  check("setup", "Election Public Key correspond to trustees",
    state.setup.payload.trustees[0][1].public_key
      === state.setup.payload.election.public_key
  );

  for (let i = 0; i < state.setup.payload.trustees.length; i++) {
    const trustee = state.setup.payload.trustees[i];
    const X = ed25519.ExtendedPoint.fromHex(rev(trustee[1].public_key));
    const challenge = BigInt(trustee[1].pok.challenge);
    const response  = BigInt(trustee[1].pok.response);

    const g_response = g.multiply(response);
    const x_challenge = X.multiply(challenge);
    const A = g_response.add(x_challenge);

    console.log(state.setup.payload.election);
    let hashedStr = `pok|${state.setup.payload.election.group}|`;
    hashedStr += `${trustee[1].public_key}|`
    hashedStr += `${rev(A.toHex())}`;

    let verificationHash = sjcl.codec.hex.fromBits(
      sjcl.hash.sha256.hash(hashedStr));
    const hexReducedVerificationHash = erem(BigInt('0x'+verificationHash), l).toString(16);

    check("setup", `Trustee ${i} POK is valid`,
      challenge.toString(16) == hexReducedVerificationHash
    );
  }
}
