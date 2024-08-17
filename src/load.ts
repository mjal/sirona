import sjcl from "sjcl";

export default function (fileEntries) {
  const state: any = {};

  state.files = fileEntries.map(readFile);

  state.setup = findData(state.files,
    findEvent(state.files, "Setup").payload);

  const electionFingerprint = sjcl.codec.base64
    .fromBits(sjcl.codec.hex.toBits(state.setup.election))
    .replace(/=+$/, "");

  state.setup = {
    ...state.setup,
    credentials: findData(state.files, state.setup.credentials),
    election: findData(state.files, state.setup.election),
    trustees: findData(state.files, state.setup.trustees),
  };
  state.setup.election.fingerprint = electionFingerprint;

  state.ballots = findEvents(state.files, "Ballot").map((ballotEvent) => {
    const hash = ballotEvent.payload;
    const ballot = findData(state.files, hash);
    ballot.hash = hash;
    ballot.tracker = sjcl.codec.base64
      .fromBits(sjcl.codec.hex.toBits(hash))
      .replace(/=+$/, "");
    return ballot;
  });

  state.shuffles = findEvents(state.files, "Shuffle").map((shuffle) => {
    shuffle.payload = findData(state.files, shuffle.payload);
    shuffle.payload.payload = findData(state.files, shuffle.payload.payload);
    return shuffle;
  });

  state.encryptedTally = findEvent(state.files, "EncryptedTally");
  if (state.encryptedTally) {
    state.encryptedTally.payload = findData(
      state.files,
      state.encryptedTally.payload,
    );
    state.encryptedTally.payload.encrypted_tally = findData(
      state.files,
      state.encryptedTally.payload.encrypted_tally,
    );
  }

  state.partialDecryptions = findEvents(state.files, "PartialDecryption").map(
    (partialDecryption) => {
      partialDecryption.payload = findData(
        state.files,
        partialDecryption.payload,
      );
      partialDecryption.payload.payload = findData(
        state.files,
        partialDecryption.payload.payload,
      );
      return partialDecryption;
    },
  );

  state.result = findEvent(state.files, "Result");
  if (state.result) {
    state.result.payload = findData(state.files, state.result.payload);
  }

  // Helpers

  // Associate owner index to trustees index and sub-index if pedersen
  state.ownerToTrusteeIndex = [
    ["Unused", -1, -1], // owners indexes start at 1, not 0
  ];
  for (let i = 0; i < state.setup.trustees.length; i++) {
    const [type, content] = state.setup.trustees[i];
    if (type === "Single") {
      state.ownerToTrusteeIndex.push(["Single", i, -1]);
    } else {
      for (let j = 0; j < content.coefexps.length; j++) {
        state.ownerToTrusteeIndex.push(["Pedersen", i, j]);
      }
    }
  }

  return state;
}

function readFile(file) {
  if (file.name === "BELENIOS") {
    return [null, "BELENIOS", JSON.parse(file.content)];
  }

  const splittedFilename = file.name.split(".");
  const hash = splittedFilename[0];
  const type = splittedFilename[1];
  const textContent = file.content;
  const jsonContent = JSON.parse(textContent);
  const hashContent = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(textContent),
  );

  if (hash !== hashContent) {
    return null;
  }

  if (hash !== hashContent) {
    throw new Error("File integrity check failed");
  }

  return [hash, type, jsonContent];
}

function findEvent(entries, eventType) {
  const entry = entries.find((entry) => {
    const [_entryHash, type, content] = entry;
    return type === "event" && content.type === eventType;
  });

  if (entry) {
    return entry[2];
  } else {
    return null;
  }
}

function findEvents(entries, eventType) {
  return entries
    .filter((entry) => {
      return entry[1] === "event" && entry[2].type === eventType;
    })
    .map((entry) => entry[2]);
}

function findData(entries, hash) {
  const entry = entries.find((entry) => {
    const [entryHash, _type, _content] = entry;
    return entryHash === hash;
  });

  if (entry) {
    return entry[2];
  } else {
    return null;
  }
}
