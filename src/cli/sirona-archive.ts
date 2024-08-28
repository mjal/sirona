#!/usr/bin/env node

import fs from "fs";
import { Command } from "commander";
import { readStdin } from "../utils";
import * as Trustee from "../Trustee";
import * as Archive from "../Archive";

const program = new Command();

program
  .command("init")
  .action(async (options) => {
    let data = await fs.promises.readFile("election.json");
    let election = JSON.parse(data.toString());

    data = await fs.promises.readFile("public_creds.json");
    let credentials = JSON.parse(data.toString());
    credentials = credentials.map((line) => {
      const [pubkey,weight] = line.split(",");
      if (weight !== undefined) {
        return pubkey + "," + weight;
      } else {
        return pubkey;
      }
    });

    data = await fs.promises.readFile("trustees.json");
    let trustees = JSON.parse(data.toString());
    trustees = trustees.map(Trustee.fromJSON);
    trustees = trustees.map(Trustee.toJSON);

    const archiveFilename = election.uuid + ".bel";

    Archive.addFile(archiveFilename, "BELENIOS", JSON.stringify({
      version: 1,
      timestamp: Math.floor(Date.now() / 1000).toString(),
    }, null, 0));

    let setup = {
      election: "",
      trustees: "",
      credentials: ""
    }

    setup.election = await Archive.addData(archiveFilename, JSON.stringify(election, null, 0));
    setup.trustees = await Archive.addData(archiveFilename, JSON.stringify(trustees, null, 0));
    setup.credentials = await Archive.addData(archiveFilename, JSON.stringify(credentials, null, 0));

    const fileHash = await Archive.addData(archiveFilename, JSON.stringify(setup, null, 0));

    await Archive.addEvent(archiveFilename, {
      parent: undefined,
      height: 0,
      type: "Setup",
      payload: fileHash,
    });
  })


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
      fileHash = await Archive.addData(archiveFilename, payload);
    }

    Archive.addEvent(archiveFilename, {
      parent: lastEventHash,
      height: JSON.parse(lastEvent.content).height + 1,
      type: options.type,
      payload: fileHash,
    });
  });

program.parseAsync(process.argv);
