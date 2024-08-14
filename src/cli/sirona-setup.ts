import fs from "fs";
import { Command } from "commander";
import * as Credential from "../Credential";

const b58chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const program = new Command();

program.command("generate-token").action(() => {
  let uuid = Array.from({ length: 14 }, (_, i) => {
    const randomIndex = Math.floor(Math.random() * b58chars.length);
    return b58chars[randomIndex];
  }).join("");

  console.log(uuid);
});

program
  .command("generate-credentials")
  .option(
    "--file <FILE>",
    "Read  identities  from  FILE.  One credential will be generated for each line of FILE.",
  )
  .option("--uuid <UUID>", "UUID of the election.")
  .action(async function (options) {
    const data = await fs.promises.readFile(options.file);
    const lines = data
      .toString()
      .split("\n")
      .filter((line) => line.length > 0);

    const privcreds = Object.fromEntries(
      lines.map((line) => {
        const [email, id, weight] = line.split(",");

        let privcred = Array.from({ length: 24 }, (_, i) => {
          if (i === 5 || i === 12 || i === 18) {
            return "-";
          }
          const randomIndex = Math.floor(Math.random() * b58chars.length);
          return b58chars[randomIndex];
        }).join("");

        return [id, privcred];
      }),
    );

    const pubcreds = lines.map((line, i) => {
      const [email, id, weight] = line.split(",");
      const privcred = privcreds[id];

      const { hPublicCredential } = Credential.derive(options.uuid, privcred);

      return `${hPublicCredential},${weight},${id}`;
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

program.parseAsync(process.argv);
