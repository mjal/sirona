import { ed25519 } from "@noble/curves/ed25519";
import { assert, check } from "./utils.js";
import { g, L, rev, mod, zero, isValidPoint, parsePoint } from "./math";
import sjcl from "sjcl";

export default function (state) {
  checkTrustees(state);
  checkElectionPublicKey(state);
  checkCredentials(state);
}

function checkTrustees(state) {
  for (let i = 0; i < state.setup.payload.trustees.length; i++) {
    const trustee = state.setup.payload.trustees[i];
    if (trustee[0] === "Single") {
      checkTrusteePublicKey(state, trustee[1]);
    } else { // "Pedersen"
      for (let j = 0; j < trustee[1].verification_keys.length; j++) {
        checkTrusteePublicKey(state, trustee[1].verification_keys[j]);
      }
    }
  }
}

function checkElectionPublicKey(state) {
  const pElectionPublicKey = parsePoint(
    state.setup.payload.election.public_key,
  );
  check(
    "setup",
    `Election Public Key is a valid curve point`,
    isValidPoint(pElectionPublicKey),
  );

  let pJointPublicKey = zero;
  for (let i = 0; i < state.setup.payload.trustees.length; i++) {
    const trustee = state.setup.payload.trustees[i];
    if (trustee[0] === "Single") {
      const pX = parsePoint(trustee[1].public_key);
      pJointPublicKey = pJointPublicKey.add(pX);
    } else {
      // "Pedersen"
      const coefexps = trustee[1].coefexps.map((o) => {
        return JSON.parse(o.message).coefexps[0];
      });
      let sum = zero;
      for (let j = 0; j < coefexps.length; j++) {
        sum = sum.add(parsePoint(coefexps[j]));
      }
      pJointPublicKey = pJointPublicKey.add(sum);
    }
  }

  check(
    "setup",
    "Election Public Key correspond to trustees",
    rev(pJointPublicKey.toHex()) === state.setup.payload.election.public_key,
  );
}

function checkTrusteePublicKey(state, trustee) {
  const pX = parsePoint(trustee.public_key);

  check("setup", `Trustee public key is a valid curve point`, isValidPoint(pX));

  const nChallenge = BigInt(trustee.pok.challenge);
  const nResponse = BigInt(trustee.pok.response);

  const pA = g.multiply(nResponse).add(pX.multiply(nChallenge));

  let hashedStr = `pok|${state.setup.payload.election.group}|`;
  hashedStr += `${trustee.public_key}|`;
  hashedStr += `${rev(pA.toHex())}`;

  const verificationHash = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(hashedStr),
  );
  const hexReducedVerificationHash = mod(
    BigInt("0x" + verificationHash),
    L,
  ).toString(16);

  check(
    "setup",
    `Trustee POK is valid`,
    nChallenge.toString(16) === hexReducedVerificationHash,
  );
}

function checkCredentials(state) {
  for (let i = 0; i < state.credentialsWeights.length; i++) {
    check("setup",
      `Credential ${i} is valid`,
      isValidPoint(parsePoint(state.credentialsWeights[i].credential))
    )
  }
}
