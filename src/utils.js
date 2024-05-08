import sjcl from "sjcl";

export let assert = console.assert;

export function readFile(file) {
  if (file.name === "BELENIOS") {
    return [null, "BELENIOS", JSON.parse(file.readAsString())];
  }

  let splittedFilename = file.name.split('.')
  const hash = splittedFilename[0];
  const type = splittedFilename[1];
  const textContent = file.readAsString();
  const jsonContent = JSON.parse(textContent);

  // Calculer le hash du contenu
  let hashContent = sjcl.hash.sha256.hash(textContent);
  hashContent = sjcl.codec.hex.fromBits(hashContent);

  assert(hash === hashContent);

  return [hash, type, jsonContent];
}

export function findEvent(entries, eventType) {
  let entry = entries.find((entry) => {
    let [entryHash, type, content] = entry;
    return type === "event" && content.type === eventType;
  });

  if (entry) {
    return entry[2];
  } else {
    return null;
  }
}

export function findData(entries, hash) {
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

export function log(message) {
  let p = document.createElement("p");
  p.textContent = message;
  document.getElementById("content").appendChild(p);
}

export function loadElection(files) {
  let setup = findEvent(files, "Setup");
  setup.payload = findData(files, setup.payload);
  setup.fingerprint = sjcl.codec.base64.fromBits(
      sjcl.codec.hex.toBits(setup.payload.election)).replace(/=+$/, '');
  setup.payload.credentials = findData(files, setup.payload.credentials);
  setup.payload.election = findData(files, setup.payload.election);
  setup.payload.trustees = findData(files, setup.payload.trustees);

  return setup;
}

export function loadBallots(files) {
  let ballots = files.filter((entry) => entry[1] === "event" && entry[2].type === "Ballot");
  ballots = ballots.map((ballot) => ballot[2]);
  ballots.map((ballot) => {
    ballot.payload = findData(files, ballot.payload);
    return ballot;
  });

  return ballots;
}
