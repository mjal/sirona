import sjcl from "sjcl";
import { g, L, rev, mod, rand, formula2, parsePoint, Hiprove, zero } from "./math";

export default function (state, credential, choicess) {

  if (!checkVotingCode(state, credential)) {
    return false;
  }

  const { nPrivateCredential } = deriveCredential(state, credential);

  for (let i = 0; i < choicess.length; i++) {
    const choices = choicess[i];
    console.log(encrypt(state, nPrivateCredential, choices));
  }

  const hH = "AlZ/yv4k5MY0H9VlAi+zQ1iWRlATlt+FWOEmrBMxnfU"

  console.log(signature(nPrivateCredential, hH));
}

export function encrypt(state, nPrivateCredential, choices) {
  const pY = parsePoint(state.setup.payload.election.public_key);
  const { hPublicCredential } = deriveCredential(state, nPrivateCredential);

  let ciphertexts = [];
  let individual_proofs = [];

  for (let i = 0; i < choices.length; i++) {
    const r = rand();
    const w = rand();
    const gPowerM = (choices[i] === 0 ? zero : g); // TODO: Try g.multiply(choices[i]) ?
    const pAlpha = g.multiply(r);
    const pBeta = pY.multiply(r).add(gPowerM);
    let iproof = [];
    let commitments = [];

    for (let j = 0; j < 2; j++) {
      iproof.push({
        challenge: rand(),
        response: rand(),
      });
    }

    for (let j = 0; j < 2; j++) {
      if (j === choices[i]) {
        const pA = g.multiply(w);
        const pB = pY.multiply(w);
        commitments.push(pA, pB);
      } else {
        const [pA, pB] = formula2(pY, pAlpha, pBeta,
          iproof[j].challenge, iproof[j].response, i);
        commitments.push(pA, pB);
      }
    }

    let nSumChallenge = BigInt(0);
    for (let j = 0; j < 2; j++) {
      if (j !== choices[i]) {
        nSumChallenge = mod(nSumChallenge + BigInt(iproof[j].challenge), L);
      }
    }

    let S = `${state.setup.fingerprint}|${hPublicCredential}|`;
    S += choices.map((c) => `${c.alpha},${c.beta}`).join(",");
    const nH = Hiprove(S, pAlpha, pBeta, ...commitments);

    for (let j = 0; j < 2; j++) {
      if (j === choices[i]) {
        iproof[j].challenge = mod(nH - nSumChallenge, L);
        iproof[j].response = mod(w - r * iproof[j].challenge, L);
      }
    }

    ciphertexts.push({
      alpha: pAlpha.toHex(),
      beta: pBeta.toHex(),
    });
    individual_proofs.push(iproof);
  }

  //let S = `${state.setup.fingerprint}|${hPublicCredential}|`;
  //S += choices.map((c) => `${c.alpha},${c.beta}`).join(",");
  //const nH = Hiprove(

  return {
    ciphertexts,
    individual_proofs,
  };
}

export function signature(nPrivateCredential, hash) {
  const w = rand();
  const pA = g.multiply(w);

  // TODO: Refactor using Hsignature
  // TODO: nChallenge = Hsignature(hash, pA);
  const hashSignature = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(`sig|${hash}|${rev(pA.toHex())}`),
  );
  const nChallenge = mod(
    BigInt("0x" + hashSignature),
    L,
  );
  const nResponse = mod(w - nPrivateCredential * nChallenge, L);

  return {
    hash: hash,
    proof: {
      challenge: nChallenge.toString(),
      response: nResponse.toString()
    }
  };
}

export function deriveCredential(state, credential) {
  const prefix = `derive_credential|${state.setup.payload.election.uuid}`;

  const x0 = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(`${prefix}|0|${credential}`),
  );

  const x1 = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(`${prefix}|1|${credential}`),
  );

  const nPrivateCredential = mod(BigInt("0x" + x0 + x1), L);
  const pPublicCredential = g.multiply(nPrivateCredential);
  const hPublicCredential = rev(pPublicCredential.toHex());

  return {
    nPrivateCredential,
    hPublicCredential
  };
}

export function checkVotingCode(state, credential) {
  if (!/[a-zA-Z0-9]{5}-[a-zA-Z0-9]{6}-[a-zA-Z0-9]{5}-[a-zA-Z0-9]{6}/.test(credential)) {
    alert("Invalid credential format");
    return false;
  }

  const { hPublicCredential } = deriveCredential(state, credential);

  const electionPublicCredentials =
    state.credentialsWeights.map((c) => c.credential);

  if (electionPublicCredentials.includes(hPublicCredential)) {
    return true;
  } else {
    alert("Incorrect voting code");
    return false;
  }
}
