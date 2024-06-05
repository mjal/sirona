import sjcl from "sjcl";
import { g, L, rev, mod, rand } from "./math";

export default function (state, credential, choices) {

  if (!checkVotingCode(state, credential)) {
    return false;
  }

  const { nPrivateCredential } = deriveCredential(state, credential);

  const H = "AlZ/yv4k5MY0H9VlAi+zQ1iWRlATlt+FWOEmrBMxnfU"
  console.log(signature(nPrivateCredential, H));
}

export function encrypt(state, plaintext) {
  console.assert(plaintext === 0 || plaintext === 1, "Invalid plaintext");

  const r = rand();
  const pY = parsePoint(state.setup.payload.election.public_key);
  const gPowerM = plaintext === 0 ? zero : g;
  const pAlpha = g.multiply(r);
  const pBeta = pY.multiply(r).add(gPowerM);

  let iproof = [];
  let commitments = []; // As, Bs

  for (let i = 0; i < 2; i++) {
    iproof.push({
      challenge: rand().toString(),
      response: rand().toString(),
    });
  }

  for (let i = 0; i < 2; i++) {
    const [pA, pB] = formula1(pY, pAlpha, pBeta,
      BigInt(iproof[i].challenge),
      BigInt(iproof[i].response), i);
    commitments.push([pA, pB]);
  }

  const w = rand();
  for (let i = 0; i < 2; i++) {
    if (i === ciphertext) {
      const pA = g.multiply(w);
      const pB = pY.multiply(w);
      commitments[i] = [pA, pB];
    }
  }
  commitments = commitments.flat();

  let nSumChallenge = BigInt(0);
  for (let i = 0; i < 2; i++) {
    if (plaintext !== i) {
      nSumChallenge = mod(nSumChallenge + BigInt(iproof[i].challenge), L);
    }
  }

  return {
    r,
    ciphertext: {
      alpha: pAlpha.toHex(),
      beta: pBeta.toHex(),
    },
    iproof,
  };
}

export function signature(nPrivateCredential, hash) {
  const w = rand();
  const pA = g.multiply(w);

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
