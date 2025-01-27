#!/usr/bin/env node

import fs from "fs";
import { Command } from "commander";
import { genUUID } from "../utils";
import * as Credential from "../Credential";
import * as Trustee from "../Trustee";
import * as Election from "../Election";

const program = new Command();

program.command("generate-token").action(() => {
  console.log(genUUID(14));
});

program
  .command("generate-credentials")
  .requiredOption("--file <FILE>", "FILE")
  .requiredOption("--uuid <UUID>", "UUID of the election.")
  .action(async function (options) {
    const data = await fs.promises.readFile(options.file);
    const lines = data
      .toString()
      .split("\n")
      .filter((line) => line.length > 0);

    const privcreds = Object.fromEntries(
      lines.map((line) => {
        const [_email, id, _weight] = line.split(",");
        const privcred = Credential.generatePriv();

        return [id, privcred];
      }),
    );

    const pubcreds = lines.map((line, i) => {
      const [email, id, weight] = line.split(",");
      const privcred = privcreds[id];

      const { pub } = Credential.derive(options.uuid, privcred);
      return `${pub},${weight},${id}`;
    });

    const timestamp = Math.floor(Date.now() / 1000);
    await fs.promises.writeFile(
      `${timestamp}.privcreds`,
      JSON.stringify(privcreds, null, 0),
    );
    await fs.promises.writeFile(
      `${timestamp}.pubcreds`,
      JSON.stringify(pubcreds, null, 0),
    );
  });

program.command("generate-trustee-key").action(async function () {
  const [privkey, pubkey] = Trustee.generate();
  await fs.promises.writeFile(
    `privkey`,
    JSON.stringify(privkey.toString(10), null, 0),
  );
  await fs.promises.writeFile(`pubkey`, JSON.stringify(pubkey, null, 0));
});

program.command("make-trustees").action(async function () {
  const data = await fs.promises.readFile("public_keys.jsons");
  const trustees = data
    .toString()
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line));

  await fs.promises.writeFile(
    `trustees.json`,
    JSON.stringify(trustees, null, 0),
  );
});

program
  .command("make-election")
  .summary("create election.json")
  .requiredOption("--uuid <UUID>")
  .requiredOption("--template <TEMPLATE>")
  .action(async function (options) {
    let data = await fs.promises.readFile(options.template);
    const template = JSON.parse(data.toString());

    data = await fs.promises.readFile("trustees.json");
    const trustees = JSON.parse(data.toString()).map(Trustee.parse);

    const public_key = Trustee.combine_keys(trustees);

    const { description, name, questions } = template;

    const election: Election.t = {
      version: 1,
      description,
      name,
      group: "Ed25519",
      public_key,
      questions,
      uuid: options.uuid,
    };

    await fs.promises.writeFile(
      `election.json`,
      JSON.stringify(Election.serialize(election), null, 0),
    );
  });

program.parseAsync(process.argv);
