import { log } from "./logger";

export default function (state) {
  let parent;
  let nEvent = 0;
  for (let i = 0; i < state.files.length; i++) {
    const [entryHash, type, content] = state.files[i];
    if (type === "event") {
      log("database", (content.parent === parent), `Event parent correspond to previous event's hash`);
      parent = entryHash;
      nEvent++;
    }
  }

  return state;
}
