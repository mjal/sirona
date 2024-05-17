import { check } from "./utils.js";

export default function (state) {
  // TODO: Check hash correspond to content

  // Check event chain
  let parent;
  let nEvent = 0;
  for (let i = 0; i < state.files.length; i++) {
    const [entryHash, type, content] = state.files[i];
    if (type === "event") {
      check(
        "database",
        "Parent field correspond to previous event's hash",
        content.parent === parent,
      );
      parent = entryHash;
      nEvent++;
    }
  }
}
