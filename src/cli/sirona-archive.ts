#!/usr/bin/env node

import { Command } from "commander";
import sjcl from "sjcl";
import * as Archive from "../Archive";
import * as Event from "../Event";
import { readStdin } from "../utils";

const program = new Command();

program
  .command("add-event")
  .requiredOption("--type <TYPE>", "Type of event.")
  .requiredOption("--uuid <UUID>")
  .action(async (options) => {
    const archiveFilename = options.uuid + ".bel";
    const files = await Archive.readFile(archiveFilename);
    const lastEvent = files
      .reverse()
      .find((file: any) => file.name.split(".")[1] === "event");
    const lastEventHash = lastEvent.name.split(".")[0];

    const data = await readStdin();
    const lines = data
      .toString()
      .split("\n")
      .filter((line) => line.length > 0);
    let fileHash = "";
    for (let i = 0; i < lines.length; i++) {
      const payload = lines[i];
      fileHash = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(payload));
      const fileName = fileHash + ".data.json";
      Archive.addFile(archiveFilename, fileName, payload);
    }

    const event: Event.t<string> = {
      parent: lastEventHash,
      height: JSON.parse(lastEvent.content).height + 1,
      type: options.type,
      payload: fileHash,
    };
    const content = JSON.stringify(Event.toJSON(event));
    const hash = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(content));
    const fileName = hash + ".event.json";
    Archive.addFile(archiveFilename, fileName, content);
  });

program.parseAsync(process.argv);
