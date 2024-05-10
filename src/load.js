import sjcl from "sjcl";
import { check } from "./utils.js";

export default function(fileEntries) {
  let state = {}

  state.files = fileEntries.map(readFile);

  state.setup = findEvent(state.files, "Setup");
  state.setup = {
    ...state.setup,
    payloadHash: state.setup.payload,
    payload: findData(state.files, state.setup.payload),
  };
  state.setup.fingerprint = sjcl.codec.base64.fromBits(
    sjcl.codec.hex.toBits(state.setup.payload.election)).replace(/=+$/, '');
  state.setup.payload = {
    ...state.setup.payload,
    credentials: findData(state.files, state.setup.payload.credentials),
    election: findData(state.files, state.setup.payload.election),
    trustees: findData(state.files, state.setup.payload.trustees),
  };

  state.ballots = state.files.filter((entry) => {
    return entry[1] === "event" && entry[2].type === "Ballot"
  })
  .map((entry) => {
    const ballot = entry[2];
    ballot.payloadHash = ballot.payload;

    // NOTE: We may want to keep the textContent to verify ballot is canonical
    // TODO: Check if we can skip this and recompute the hash given
    // by JSON.stringify (in checkBallot.js)
    let data = state.files.find((entry) => {
      let [entryHash, type, content, textContent] = entry;
      return entryHash === ballot.payloadHash;
    });

    let [entryHash, type, content, textContent] = data;
    ballot.payloadStr = textContent;
    ballot.payload = content;

    return ballot;
  });

  state.encryptedTally = findEvent(state.files, "EncryptedTally");
  state.encryptedTally.payload =
    findData(state.files, state.encryptedTally.payload);
  state.encryptedTally.payload.encrypted_tally =
    findData(state.files, state.encryptedTally.payload.encrypted_tally);

  return state;
}

function readFile(file) {
  if (file.name === "BELENIOS") {
    return [null, "BELENIOS", JSON.parse(file.readAsString())];
  }

  let splittedFilename = file.name.split('.')
  const hash = splittedFilename[0];
  const type = splittedFilename[1];
  const textContent = file.readAsString();
  const jsonContent = JSON.parse(textContent);
  const hashContent = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(textContent));

  check(
    "database", "File hash is correct",
    hash === hashContent);

  return [hash, type, jsonContent, textContent];
}

function findEvent(entries, eventType) {
  let entry = entries.find((entry) => {
    let [entryHash, type, content, textContent] = entry;
    return type === "event" && content.type === eventType;
  });

  if (entry) {
    return entry[2];
  } else {
    return null;
  }
}

function findData(entries, hash) {
  let entry = entries.find((entry) => {
    let [entryHash, type, content] = entry;
    return entryHash === hash;
  });

  if (entry) {
    return entry[2];
  } else {
    return null;
  }
}

