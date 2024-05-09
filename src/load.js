import sjcl from "sjcl";
import { findEvent, findData } from "./utils.js";

export default function(files) {
  let state = {}

  state.files = files;

  state.setup = findEvent(files, "Setup");
  state.setup.payload = findData(files, state.setup.payload);
  state.setup.fingerprint = sjcl.codec.base64.fromBits(
      sjcl.codec.hex.toBits(state.setup.payload.election)).replace(/=+$/, '');
  state.setup.payload.credentials =
    findData(files, state.setup.payload.credentials);
  state.setup.payload.election = findData(files, state.setup.payload.election);
  state.setup.payload.trustees = findData(files, state.setup.payload.trustees);

  state.ballots = files.filter((entry) => {
    return entry[1] === "event" && entry[2].type === "Ballot"
  }).map((entry) => entry[2])
  .map((ballot) => {
    ballot.payload = findData(files, ballot.payload);
    return ballot;
  });

  return state;
}


