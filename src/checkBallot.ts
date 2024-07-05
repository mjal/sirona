import sjcl from "sjcl";
import { logBallot } from "./logger";
import {
  g,
  isValidPoint,
  parsePoint,
  formula,
  Hsignature,
} from "./math";

import * as Answer from "./Answer";
import * as Ciphertext from "./ciphertext";
import * as Election from "./election";
import * as Event from "./event";
import * as Ballot from "./ballot";

import canonicalBallot from "./canonicalBallot";

export default function (state: any, ballot: Event.t<Ballot.t>) {
  const election = state.setup.payload.election;
  checkMisc(ballot, election, state.electionFingerprint);
  checkCredential(ballot, state.credentialsWeights);
  checkIsUnique(ballot);
  checkValidPoints(ballot, election);
  checkSignature(ballot, election);

  for (let i = 0; i < state.setup.payload.election.questions.length; i++) {
    Answer.check(election,
                 state.electionFingerprint,
                 ballot.payload,
                 state.setup.payload.election.questions[i],
                 ballot.payload.answers[i]);
  }
}

function checkMisc(ballot: Event.t<Ballot.t>, election: Election.t, electionFingerprint: string) {
  const sSerializedBallot = JSON.stringify(canonicalBallot(ballot.payload, election));

  logBallot(
    ballot.tracker, 
    election.uuid === ballot.payload.election_uuid &&
    electionFingerprint === ballot.payload.election_hash,
    "election.uuid correspond to election uuid"
  );

  logBallot(
    ballot.tracker,
    sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(sSerializedBallot)) ===
      ballot.payloadHash,
    "Is canonical"
  );
}

export function hashWithoutSignature(ballot: Event.t<Ballot.t>, election: Election.t) {
  const copy = Object.assign({}, canonicalBallot(ballot.payload, election));
  delete copy.signature;
  const serialized = JSON.stringify(copy);
  const hash = sjcl.codec.base64.fromBits(sjcl.hash.sha256.hash(serialized));
  return hash.replace(/=+$/, "");
}

function checkCredential(ballot: Event.t<Ballot.t>, credentialsWeights: any) {
  const credentials = credentialsWeights.map((cw) => cw.credential);

  logBallot(
    ballot.tracker,
    credentials.indexOf(ballot.payload.credential) !== -1,
    "Has a valid credential",
  );
}

const processedBallots = {};

export function resetProcessedBallots() {
  for (const key in processedBallots) {
    delete processedBallots[key];
  }
}

function checkIsUnique(ballot: any) {
  logBallot(
    ballot.tracker,
    processedBallots[ballot.payloadHash] === undefined,
    "Is unique",
  );

  processedBallots[ballot.payloadHash] = ballot;
}

export function checkSignature(ballot: Event.t<Ballot.t>, election: Election.t) {
  logBallot(
    ballot.tracker,
    ballot.payload.signature.hash === hashWithoutSignature(ballot, election),
    "Hash without signature is correct",
  );

  const signature = ballot.payload.signature;
  const nChallenge = BigInt(signature.proof.challenge);
  const nResponse = BigInt(signature.proof.response);

  const pA = formula(
    g,
    nResponse,
    parsePoint(ballot.payload.credential),
    nChallenge,
  );
  const nH = Hsignature(signature.hash, pA);

  logBallot(
    ballot.tracker,
    nChallenge === nH,
    "Valid signature",
  );
}

export function checkValidPoints(ballot: Event.t<Ballot.t>, election: Election.t) {
  const answers = ballot.payload.answers;

  const check = (choice: Ciphertext.Serialized.t) => {
    const ct = Ciphertext.parse(choice);
    logBallot(
      ballot.tracker,
      isValidPoint(ct.pAlpha) && isValidPoint(ct.pBeta),
      "Encrypted choices alpha,beta are valid curve points",
    );
  };

  for (let i = 0; i < answers.length; i++) {
    const answer = answers[i];
    if (Answer.Serialized.IsAnswerH(answer, election.questions[i])) {
      for (let j = 0; j < answer.choices.length; j++) {
        check(answer.choices[i]);
      }
    } else if (Answer.Serialized.IsAnswerL(answer, election.questions[i])) {
      for (let j = 0; j < answer.choices.length; j++) {
        for (let k = 0; k < answer.choices[j].length; k++) {
          check(answer.choices[j][k]);
        }
      }
    } else if (Answer.Serialized.IsAnswerNH(answer, election.questions[i])) {
      check(answer.choices);
    }
  }
}
