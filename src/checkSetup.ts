import { g, rev, zero, isValidPoint, parsePoint, Hpok } from "./math";

export default function (state: any) {
  return checkTrustees(state)
  && checkElectionPublicKey(state)
  && checkCredentials(state);
}

function checkTrustees(state: any) {
  for (let i = 0; i < state.setup.payload.trustees.length; i++) {
    const trustee = state.setup.payload.trustees[i];
    if (trustee[0] === "Single") {
      if (!checkTrusteePublicKey(state, trustee[1])) {
        return false;
      }
    } else {
      // "Pedersen"
      for (let j = 0; j < trustee[1].verification_keys.length; j++) {
        if (checkTrusteePublicKey(state, trustee[1].verification_keys[j])) {
          return false;
        }
      }
    }
  }
  return true;
}

function checkElectionPublicKey(state: any) {
  const pElectionPublicKey = parsePoint(
    state.setup.payload.election.public_key,
  );
  if (!isValidPoint(pElectionPublicKey)) {
    throw new Error("Invalid curve point");
  }

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

  if (rev(pJointPublicKey.toHex()) !== state.setup.payload.election.public_key) {
    throw new Error("Election Public Key doesn't correspond to trustees")
  }
  
  return true;
}

function checkTrusteePublicKey(state: any, trustee: any) {
  const pX = parsePoint(trustee.public_key);

  if (!isValidPoint(pX)) {
    throw new Error("Invalid curve point");
  }

  const nChallenge = BigInt(trustee.pok.challenge);
  const nResponse = BigInt(trustee.pok.response);

  const pA = g.multiply(nResponse).add(pX.multiply(nChallenge));

  const S = `${state.setup.payload.election.group}|${trustee.public_key}`;

  if (Hpok(S, pA) !== nChallenge) {
    throw new Error("Trustee POK is invalid");
  }
  return true;
}

function checkCredentials(state: any) {
  for (let i = 0; i < state.credentialsWeights.length; i++) {
    if (!isValidPoint(parsePoint(state.credentialsWeights[i].credential))) {
      throw new Error(`Credential ${i} is invalid`);
    }
  }
  return true;
}
