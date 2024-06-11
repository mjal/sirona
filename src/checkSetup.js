import { log } from "./logger";
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
    } else {
      // "Pedersen"
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
  log(
    "setup",
    isValidPoint(pElectionPublicKey),
    `Election Public Key is a valid curve point`
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

  log(
    "setup",
    rev(pJointPublicKey.toHex()) === state.setup.payload.election.public_key,
    "Election Public Key correspond to trustees",
  );
}

function checkTrusteePublicKey(state, trustee) {
  const pX = parsePoint(trustee.public_key);

  log("setup", isValidPoint(pX), `Trustee public key is a valid curve point`);

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

  log(
    "setup",
    nChallenge.toString(16) === hexReducedVerificationHash,
    `Trustee POK is valid`
  );
}

function checkCredentials(state) {
  for (let i = 0; i < state.credentialsWeights.length; i++) {
    log(
      "setup",
      isValidPoint(parsePoint(state.credentialsWeights[i].credential)),
      `Credential ${i} is valid`,
    );
  }
}
