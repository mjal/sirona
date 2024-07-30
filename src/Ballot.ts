import sjcl from "sjcl";
import * as Event from "./Event";
import * as Proof from "./Proof";
import * as Point from "./Point";
import * as Answer from "./Answer";
import * as Election from "./Election";
import canonicalBallot from "./canonicalBallot";
import { g, formula, Hsignature } from "./math";

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

// -- Verify

export function verify(state: any, ballotEvent: Event.t<t>) {
  const ballot = ballotEvent.payload;
  const election = state.setup.payload.election;
  checkMisc(
    ballot,
    ballotEvent.payloadHash,
    election
  );
  checkCredential(ballot, state.credentialsWeights);
  checkIsUnique(ballot, ballotEvent.payloadHash);
  checkSignature(ballot, election);

  for (let i = 0; i < state.setup.payload.election.questions.length; i++) {
    Answer.verify(
      election,
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
) {
  const sSerializedBallot = JSON.stringify(canonicalBallot(ballot, election));

  if (
    !(
      election.uuid === ballot.election_uuid &&
      election.fingerprint === ballot.election_hash
    )
  ) {
    throw new Error("election_uuid or election_hash is incorrect");
  }

  const hash = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(sSerializedBallot),
  );

  if (hash !== ballotPayloadHash) {
    throw new Error("Ballot payload is not canonical");
  }
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

  if (credentials.indexOf(ballot.credential) === -1) {
    throw new Error("Credential is not valid");
  }
}

const processedBallots = {};

export function resetProcessedBallots() {
  for (const key in processedBallots) {
    delete processedBallots[key];
  }
}

function checkIsUnique(ballot: t, ballotPayloadHash: string) {
  if (processedBallots[ballotPayloadHash] !== undefined) {
    throw new Error("Ballot is not unique");
  }
  processedBallots[ballotPayloadHash] = ballot;
}

export function checkSignature(ballot: t, election: Election.t) {
  if (ballot.signature.hash !== hashWithoutSignature(ballot, election)) {
    throw new Error("Hash without signature is incorrect");
  }

  const signature = ballot.signature;
  const nChallenge = BigInt(signature.proof.challenge);
  const nResponse = BigInt(signature.proof.response);

  const pA = formula(g, nResponse, Point.parse(ballot.credential), nChallenge);
  const nH = Hsignature(signature.hash, pA);

  if (nH !== nChallenge) {
    throw new Error("Invalid signature");
  }
}
