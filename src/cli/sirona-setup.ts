import fs from "fs";
import { Command } from "commander";

const program = new Command();

program.command("generate-token")
  .action(() => {
    const chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  
    let uuid = Array.from({ length: 14 }, (_, i) => {
      const randomIndex = Math.floor(Math.random() * chars.length);
      return chars[randomIndex];
    }).join('');
  
    console.log(uuid);
  });

program.command("generate-credentials")
  .option("--file <FILE>", "Read  identities  from  FILE.  One credential will be generated for each line of FILE.")
  .action(async function (options) {
    const data = await fs.promises.readFile(options.file);
    const lines = data.toString().split("\n");
    lines.forEach((line) => {
      const [email, id, weight] = line.split(",");
      console.log(`${id} ${email} ${weight}`);
    });
    console.log(data);
  });

program.parseAsync(process.argv);
