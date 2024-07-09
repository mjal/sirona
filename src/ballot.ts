import sjcl from "sjcl";
import * as Event from "./event";
import * as Proof from "./proof";
import * as Answer from "./Answer";
import * as Election from "./election";
import canonicalBallot from "./canonicalBallot";
import { logBallot } from "./logger";
import { g, parsePoint, formula, Hsignature } from "./math";

export type t = {
  election_uuid: string;
  election_hash: string;
  credential: string;
  answers: Array<Answer.Serialized.t>;
  signature: {
    hash: string;
    proof: Proof.Serialized.t;
  };
};

// -- Check

export function check(state: any, ballotEvent: Event.t<t>) {
  const ballot = ballotEvent.payload;
  const election = state.setup.payload.election;
  checkMisc(
    ballot,
    ballotEvent.payloadHash,
    election,
    state.electionFingerprint,
  );
  checkCredential(ballot, state.credentialsWeights);
  checkIsUnique(ballot, ballotEvent.payloadHash);
  checkSignature(ballot, election);

  for (let i = 0; i < state.setup.payload.election.questions.length; i++) {
    Answer.check(
      election,
      state.electionFingerprint,
      ballot,
      state.setup.payload.election.questions[i],
      ballot.answers[i],
    );
  }
}

function checkMisc(
  ballot: t,
  ballotPayloadHash: string,
  election: Election.t,
  electionFingerprint: string,
) {
  const sSerializedBallot = JSON.stringify(canonicalBallot(ballot, election));

  logBallot(
    ballot.signature.hash,
    election.uuid === ballot.election_uuid &&
      electionFingerprint === ballot.election_hash,
    "election_uuid and election_hash are corrects",
  );

  logBallot(
    ballot.signature.hash,
    sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(sSerializedBallot)) ===
      ballotPayloadHash,
    "Is canonical",
  );
}

export function hashWithoutSignature(ballot: t, election: Election.t) {
  const copy = Object.assign({}, canonicalBallot(ballot, election));
  delete copy.signature;
  const serialized = JSON.stringify(copy);
  const hash = sjcl.codec.base64.fromBits(sjcl.hash.sha256.hash(serialized));
  return hash.replace(/=+$/, "");
}

function checkCredential(ballot: t, credentialsWeights: any) {
  const credentials = credentialsWeights.map((cw) => cw.credential);

  logBallot(
    ballot.signature.hash,
    credentials.indexOf(ballot.credential) !== -1,
    "Has a valid credential",
  );
}

const processedBallots = {};

export function resetProcessedBallots() {
  for (const key in processedBallots) {
    delete processedBallots[key];
  }
}

function checkIsUnique(ballot: t, ballotPayloadHash: string) {
  logBallot(
    ballot.signature.hash,
    processedBallots[ballotPayloadHash] === undefined,
    "Is unique",
  );

  processedBallots[ballotPayloadHash] = ballot;
}

export function checkSignature(ballot: t, election: Election.t) {
  logBallot(
    ballot.signature.hash,
    ballot.signature.hash === hashWithoutSignature(ballot, election),
    "Hash without signature is correct",
  );

  const signature = ballot.signature;
  const nChallenge = BigInt(signature.proof.challenge);
  const nResponse = BigInt(signature.proof.response);

  const pA = formula(g, nResponse, parsePoint(ballot.credential), nChallenge);
  const nH = Hsignature(signature.hash, pA);

  logBallot(ballot.signature.hash, nChallenge === nH, "Valid signature");
}
