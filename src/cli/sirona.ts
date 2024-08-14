import sjcl from "sjcl";
import { Command } from "commander";
import { readStdin } from "../utils";

const program = new Command();

program
  .name("sirona")
  .description("belenios compatible implementation")
  .version("0.0.1")
  .command("setup", "Setup related commands")
  .command("election", "Election related commands")
  .command("archive", "Archive related commands");

program.command("sha256-b64").action(() => {
  readStdin().then((data: any) => {
    const hash = sjcl.codec.base64.fromBits(sjcl.hash.sha256.hash(data));
    console.log(hash);
  });
});

program.parseAsync(process.argv);
