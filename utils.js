import sjcl from "sjcl";
import untar from "js-untar";

export let assert = console.assert;

export function readTar(filename, then) {
  fetch(filename)
    .then(response => {
      if (response.ok) {
        return response.arrayBuffer();
      } else {
        throw new Error('Error fetching file');
      }
    })
    .then(data => {
      untar(data).then(then)
    })
}

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
  let election = findEvent(files, "Setup");
  election.payload = findData(files, election.payload);
  election.payload.credentials = findData(files, election.payload.credentials);
  election.payload.election = findData(files, election.payload.election);
  election.payload.trustees = findData(files, election.payload.trustees);

  return election;
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


/*
function typeOfFile(file) {
  if (file.name == "BELENIOS") {
    return "manifest";
  }

  const extension = file.name.split('.')[1];
  if (extension != "data" && extension != "event") {
    throw "Unknown file type"
  }

  return extension;
}
*/

/*
function readData(file) {
  let splittedFilename = file.name.split('.')
  const hash = splittedFilename[0];
  const extension = splittedFilename[1];
  console.assert(extension === "data");
  state.data[hash] = JSON.parse(file.readAsString());
}
*/

/*
// TODO: Check hashs
function readNextEvent(files, then) {
  console.assert (files.length != 0);
  let first = files[0];
  files = files.slice(1, files.length);
  let type = typeOfFile(first);

  if (type == "manifest") {
    state.manifest = JSON.parse(first.readAsString());
    then()
    return
  }
  console.assert (type == "event");
  let event = JSON.parse(first.readAsString());
  let payload;
  switch (event.type) {
    case "Result":
      readData(files[0]);
      payload = files[0];
      files = files.slice(1, files.length);
      event.payload = JSON.parse(payload.readAsString());
      state.result = JSON.parse(payload.readAsString());
      readNextEvent(files, then);
      break;
    case "PartialDecryption":
      readData(files[0]);
      payload = files[0];
      files = files.slice(1, files.length);
      event.it_s = JSON.parse(payload.readAsString());
      readData(files[0]);
      payload = files[0];
      files = files.slice(1, files.length);
      event.payload = JSON.parse(payload.readAsString());
      state.partialDecryptions.push(JSON.parse(payload.readAsString()));
      readNextEvent(files, then);
      break;
    case "EncryptedTally":
      readData(files[0]);
      payload = files[0];
      files = files.slice(1, files.length);
      event.et_s = JSON.parse(payload.readAsString());
      readData(files[0]);
      payload = files[0];
      files = files.slice(1, files.length);
      state.encryptedTally = event;
      readNextEvent(files, then);
      break;
    case "EndBallots":
      readNextEvent(files, then);
      break;
    case "Ballot":
      state.ballots.push(event);
      readData(files[0]);
      files = files.slice(1, files.length);
      readNextEvent(files, then);
      break;
    case "Setup":
      state.election = event;
      readData(files[0]);
      files = files.slice(1, files.length);
      readData(files[0]);
      files = files.slice(1, files.length);
      readData(files[0]);
      files = files.slice(1, files.length);
      readData(files[0]);
      files = files.slice(1, files.length);
      readNextEvent(files, then);
      break;
    default:
      throw `Unknown event ${event.type}`;
  }

  console.log(event);
}
*/

