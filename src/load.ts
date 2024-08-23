import sjcl from "sjcl";
import * as Ballot from "./Ballot";
import * as Shuffle from "./Shuffle";
import * as Setup from "./Setup";
import * as Trustee from "./Trustee";
import * as EncryptedTally from "./EncryptedTally";
import * as PartialDecryption from "./PartialDecryption";
import * as Result from "./Result";

export type t = {
  setup: Setup.t;
  ballots: Array<Ballot.t>;
  shuffles: Array<Shuffle.t>;
  encryptedTally: EncryptedTally.t;
  partialDecryptions: Array<PartialDecryption.t>;
  result: Result.t;
};

namespace File {
  export type t = [string, string, any];
}

export default function (rawFiles : Array<any>) {
  const files = rawFiles.map(readFile);

  let height = 0;
  let parent: string = undefined;
  for (let i = 0; i < files.length; i++) {
    const [contentHash, type, content] = files[i];

    if (type === "event") {

      if (content.parent !== parent) {
        throw new Error(
          "Invalid event parent hash",
        );
      }

      if (content.height !== height) {
        throw new Error(
          "Invalid event height",
        );
      }

      parent = contentHash;
      height++;
    }
  }

  /* @ts-ignore */
  const state : t = {};

  const setup = findData(files, findEvent(files, "Setup").payload);
  state.setup = {
    ...setup,
    credentials: findData(files, setup.credentials),
    election: findData(files, setup.election),
    trustees: findData(files, setup.trustees).map(Trustee.fromJSON),
  };

  const alreadyProcessedBallots = {};
  state.ballots = findEvents(files, "Ballot").map((ballotEvent) => {
    const hash = ballotEvent.payload;
    const ballot = findData(files, hash);

    const canonicalBallot = JSON.stringify(Ballot.toJSON(ballot, state.setup.election));
    const recomputedHash = sjcl.codec.hex.fromBits(
      sjcl.hash.sha256.hash(canonicalBallot),
    );

    if (hash !== recomputedHash) {
      throw new Error("Ballot is not canonical");
    }

    if (alreadyProcessedBallots[hash]) {
      throw new Error("Ballot is not unique");
    }
    alreadyProcessedBallots[hash] = true;

    /*
     * TODO: Remove everywhere
    */
    ballot.hash = hash;
    ballot.tracker = sjcl.codec.base64
      .fromBits(sjcl.codec.hex.toBits(hash))
      .replace(/=+$/, "");

    return ballot;
  });

  state.shuffles = findEvents(files, "Shuffle").map((shuffle) => {
    const ret = findData(files, shuffle.payload);
    ret.payload = findData(files, ret.payload);
    return Shuffle.parse(ret);
  });

  const encryptedTallyEvent = findEvent(files, "EncryptedTally");
  if (encryptedTallyEvent) {
    state.encryptedTally = findData(
      files,
      encryptedTallyEvent.payload,
    );
    state.encryptedTally.encrypted_tally = findData(
      files, /* @ts-ignore */
      state.encryptedTally.encrypted_tally,
    );
  }

  state.partialDecryptions = findEvents(files, "PartialDecryption").map(
    (event) => {
      event.payload = findData(
        files,
        event.payload,
      );
      event.payload.payload = findData(
        files,
        event.payload.payload,
      );
      return event.payload;
    },
  );

  const resultEvent = findEvent(files, "Result");
  if (resultEvent) {
    state.result = findData(files, resultEvent.payload);
  }

  return state;
}

function readFile(file: any) : File.t {
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
    throw new Error("File integrity check failed");
  }

  return [hash, type, jsonContent];
}

function findEvent(files: File.t[], eventType: string) {
  const file = files.find((file) => {
    const [_contentHash, type, content] = file;

    return type === "event" && content.type === eventType;
  });

  if (file) {
    const [_contentHash, _type, content] = file;

    return content;
  } else {
    return null;
  }
}

function findEvents(files: File.t[], eventType: string) {
  return files.filter((file: File.t) => {
    const [_contentHash, type, content] = file;

    return type === "event" && content.type === eventType;
  }).map((file: File.t) => {
    const [_contentHash, _type, content] = file;

    return content;
  });
}

function findData(files: File.t[], hash: string) {
  const file = files.find((file) => {
    const [contentHash, _type, _content] = file;

    return contentHash === hash;
  });

  if (file) {
    const [_contentHash, _type, content] = file;

    return content;
  } else {
    return null;
  }
}
