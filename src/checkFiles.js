import { logSuccess, assert } from "./utils.js";

export default function(state) {
  // TODO: Check hash correspond to content

  // TODO: Check event are in canonical form

  // Check event chain
  let parent = undefined;
  let nEvent = 0;
  for (let i = 0; i < state.files.length; i++) {
    let [entryHash, type, content] = state.files[i];
    if (type === "event") {
      assert(content.parent == parent);
      parent = entryHash;
      nEvent++;
    }
  }

  logSuccess("database", `Checked ${nEvent} events`);
}


