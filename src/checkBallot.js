import sjcl from "sjcl";
import { ed25519 } from "@noble/curves/ed25519";
import { check, assert, logSuccess, logError } from "./utils.js";
import { g, l, rev, erem } from "./math.js";

export default function (state, ballot) {
  assert(state.setup.payload.election.uuid === ballot.payload.election_uuid);

  checkIsCanonical(ballot);
  checkCredential(state, ballot);
  checkIsUnique(ballot);

  checkSignature(ballot);
  checkIndividualProofs(state, ballot);
  checkOverallProof(state, ballot);
}

function valuesForProofOfIntervalMembership(y, alpha, beta, transcripts, ms) {
  const values = [];

  for (let i = 0; i < transcripts.length; i++) {
    const m = ms[i];

    const challenge = BigInt(transcripts[i].challenge);
    const response = BigInt(transcripts[i].response);

    const a = g.multiply(response).add(alpha.multiply(challenge));
    const gPowerM =
      m === 0 ? ed25519.ExtendedPoint.ZERO : g.multiply(BigInt(m));
    const b = y
      .multiply(response)
      .add(beta.add(gPowerM.negate()).multiply(challenge));

    values.push(a);
    values.push(b);
  }

  return values;
}

function hashWithoutSignature(ballot) {
  const copy = Object.assign({}, ballot.payload);
  delete copy.signature;
  const serialized = JSON.stringify(copy);
  const hash = sjcl.codec.base64.fromBits(sjcl.hash.sha256.hash(serialized));
  return hash.replace(/=+$/, "");
}

function checkIsCanonical(ballot) {
  // On most implementations, the order of the fields in the
  // serialization correspond to the order of insertion. This
  // is not guaranteed by the JSON standard, but it is guaranteed
  // by JSON.stringify in most implementations.
  const obj = {
    election_uuid: ballot.payload.election_uuid,
    election_hash: ballot.payload.election_hash,
    credential: ballot.payload.credential,
    answers: ballot.payload.answers.map((answer) => {
      let obj = {};
      if (answer.choices.length === undefined) {
        obj.choices = {
          alpha: answer.choices.alpha,
          beta: answer.choices.beta,
        };
      } else {
        obj.choices = answer.choices.map((choice) => {
          return {
            alpha: choice.alpha,
            beta: choice.beta,
          };
        });
      }
      if (answer.proof) {
        obj.proof = {
          challenge: answer.proof.challenge,
          response: answer.proof.response,
        };
      }
      if (answer.individual_proofs) {
        obj.individual_proofs = answer.individual_proofs.map((iproof) => {
          return iproof.map((proof) => {
            return {
              challenge: proof.challenge,
              response: proof.response,
            };
          });
        });
      }
      if (answer.overall_proof) {
        obj.overall_proof = answer.overall_proof.map((proof) => {
          return {
            challenge: proof.challenge,
            response: proof.response,
          };
        });
      }
      if (answer.blank_proof !== undefined) {
        obj.blank_proof = answer.blank_proof.map((proof) => {
          return {
            challenge: proof.challenge,
            response: proof.response,
          };
        });
      }
      return obj;
    }),
    signature: ballot.payload.signature,
  };
  check(
    "ballots",
    "Is canonical",
    sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(JSON.stringify(obj))) ===
      ballot.payloadHash,
  );
}

function checkCredential(state, ballot) {
  const credentials = state.setup.credentialsWeights.map((cw) => cw.credential);
  check(
    "ballots",
    "Has a valid credential",
    credentials.indexOf(ballot.payload.credential) !== -1,
  );
}

const processedBallots = {};

function checkIsUnique(ballot) {
  check(
    "ballots",
    "Is unique",
    processedBallots[ballot.payload.credential] === undefined,
  );

  processedBallots[ballot.payload.credential] = ballot;
}

export function checkSignature(ballot) {
  assert(ballot.payload.signature.hash === hashWithoutSignature(ballot));
  logSuccess("ballots", "Hashes are equal");

  const credential = ed25519.ExtendedPoint.fromHex(
    rev(ballot.payload.credential),
  );

  const signature = ballot.payload.signature;

  const challenge = BigInt(signature.proof.challenge);
  const response = BigInt(signature.proof.response);

  const A = g.multiply(response).add(credential.multiply(challenge));

  const H = ballot.payload.signature.hash;

  const verificationHash = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(`sig|${H}|${rev(A.toHex())}`),
  );

  const hexReducedVerificationHash = erem(
    BigInt("0x" + verificationHash),
    l,
  ).toString(16);

  assert(challenge.toString(16) === hexReducedVerificationHash);
  logSuccess("ballots", "Valid signature");
}

export function checkIndividualProofs(state, ballot) {
  let y = state.setup.payload.election.public_key;
  y = ed25519.ExtendedPoint.fromHex(rev(y));

  const answers = ballot.payload.answers;
  for (let i = 0; i < answers.length; i++) {
    const question = state.setup.payload.election.questions[i];
    if (question.type === "NonHomomorphic") {
      continue;
    }
    const answer = answers[i];
    const choices = answer.choices;
    const individualProofs = answer.individual_proofs;

    assert(
      individualProofs.length ===
        state.setup.payload.election.questions[i].answers.length,
    );
    for (let j = 0; j < individualProofs.length; j++) {
      const alpha = ed25519.ExtendedPoint.fromHex(rev(choices[j].alpha));
      const beta = ed25519.ExtendedPoint.fromHex(rev(choices[j].beta));
      // TODO: Check alpha, beta are on the curve

      let sumChallenges = 0n;
      for (let k = 0; k < individualProofs[j].length; k++) {
        const challenge = BigInt(individualProofs[j][k].challenge);
        sumChallenges = erem(sumChallenges + challenge, l);
      }

      const values = valuesForProofOfIntervalMembership(
        y,
        alpha,
        beta,
        individualProofs[j],
        [0, 1],
      );

      const S = `${state.setup.fingerprint}|${ballot.payload.credential}`;
      let challengeStr = `prove|${S}|${choices[j].alpha},${choices[j].beta}|`;
      challengeStr += values.map((v) => rev(v.toHex())).join(",");

      const verificationHash = sjcl.codec.hex.fromBits(
        sjcl.hash.sha256.hash(challengeStr),
      );
      const hexReducedVerificationHash = erem(
        BigInt("0x" + verificationHash),
        l,
      ).toString(16);

      assert(sumChallenges.toString(16) === hexReducedVerificationHash);
      logSuccess("ballots", "Valid individual proof");
    }
  }
}

export function checkOverallProof(state, ballot) {
  let y = state.setup.payload.election.public_key;
  y = ed25519.ExtendedPoint.fromHex(rev(y));

  for (let i = 0; i < ballot.payload.answers.length; i++) {
    const question = state.setup.payload.election.questions[i];
    if (question.type === "NonHomomorphic") {
      continue;
    }
    if (question.blank) {
      // TODO:
      logError("ballots", "Question with blank vote not implemented yet");
      continue;
    }
    console.log(question);

    const answer = ballot.payload.answers[i];

    const sumc = {
      alpha: ed25519.ExtendedPoint.ZERO,
      beta: ed25519.ExtendedPoint.ZERO,
    };

    for (let j = 0; j < answer.choices.length; j++) {
      sumc.alpha = sumc.alpha.add(
        ed25519.ExtendedPoint.fromHex(rev(answer.choices[j].alpha)),
      );
      sumc.beta = sumc.beta.add(
        ed25519.ExtendedPoint.fromHex(rev(answer.choices[j].beta)),
      );
    }

    let sumChallenges = 0n;
    for (let k = 0; k < answer.overall_proof.length; k++) {
      const challenge = BigInt(answer.overall_proof[k].challenge);
      sumChallenges = erem(sumChallenges + challenge, l);
    }

    const min = state.setup.payload.election.questions[i].min;
    const max = state.setup.payload.election.questions[i].max;
    const ms = [];
    for (let j = min; j <= max; j++) {
      ms.push(j);
    }
    const values = valuesForProofOfIntervalMembership(
      y,
      sumc.alpha,
      sumc.beta,
      answer.overall_proof,
      ms,
    );

    let challengeStr = "prove|";
    challengeStr += `${state.setup.fingerprint}|${ballot.payload.credential}|`;
    const alphasBetas = [];
    for (let j = 0; j < answer.choices.length; j++) {
      alphasBetas.push(`${answer.choices[j].alpha},${answer.choices[j].beta}`);
    }
    challengeStr += alphasBetas.join(",");
    challengeStr += `|${rev(sumc.alpha.toHex())},${rev(sumc.beta.toHex())}|`;
    challengeStr += values.map((v) => rev(v.toHex())).join(",");

    const verificationHash = sjcl.codec.hex.fromBits(
      sjcl.hash.sha256.hash(challengeStr),
    );
    const hexReducedVerificationHash = erem(
      BigInt("0x" + verificationHash),
      l,
    ).toString(16);

    assert(sumChallenges.toString(16) === hexReducedVerificationHash);
    logSuccess("ballots", "Valid overall proof");
  }
}
