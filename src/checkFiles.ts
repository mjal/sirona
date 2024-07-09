export default function (state) {
  let parent : string = undefined;
  let nEvent = 0;
  for (let i = 0; i < state.files.length; i++) {
    const [entryHash, type, content] = state.files[i];
    if (type === "event") {
      if (content.parent !== parent) {
        throw new Error("Event parent does not correspond to previous event's hash");
      }
      parent = entryHash;
      nEvent++;
    }
  }

  return true;
}
