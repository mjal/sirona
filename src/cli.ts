import fs from "fs";
import { Command } from 'commander';
import { TarReader } from "./tarReader";
import { getLogs, getBallotLogs } from "./logger";
import generateBallot from "./generateBallot";
import canonicalBallot from "./canonicalBallot";
import check from "./check";

const program = new Command();
let errors = 0;

program
  .name('sirona')
  .description('belenios compatible implementation')
  .version('0.0.1');

const electionCommand = program
  .command('election')
  .description('Election related commands')

electionCommand
  .command('verify')
  .argument('<filename>', 'database file (.bel)')
  .option('-q, --quiet',  'only show the final result')
  .action(async function (filename, options) {
    const checkFile = async (filePath) => {
      const data = await fs.promises.readFile(filePath);

      const tarReader = new TarReader(data);
      const files = tarReader.getFiles();
      const state = await check(files);

      const sectionLogs = getLogs();
      const sections = Object.keys(sectionLogs);
      for (let i = 0; i < sections.length; i++) {
        const logs = sectionLogs[sections[i]];
        if (!options.quiet)
          console.log("=== " + sections[i] + " ===");
        for (let j = 0; j < logs.length; j++) {
          if (!logs[j].pass) { errors++; }
          const prefix = logs[j].pass ? "✅" : "❌";
          if (!options.quiet)
            console.log(prefix + logs[j].message);
        }
      }
      
      const ballotLogs = getBallotLogs();
      const ballotKeys = Object.keys(ballotLogs);
      if (!options.quiet)
        console.log("=== BALLOTS ===");
      for (let i = 0; i < ballotKeys.length; i++) {
        const logs = ballotLogs[ballotKeys[i]];
        if (!options.quiet)
          console.log("=== " + ballotKeys[i] + " ===");
        for (let j = 0; j < logs.length; j++) {
          if (!logs[j].pass) { errors++; }
          const prefix = logs[j].pass ? "✅" : "❌";
          if (!options.quiet)
            console.log(prefix + logs[j].message);
        }
      }
    }

    await checkFile(filename);
    console.log(`${errors} errors found.`);

    process.exit(errors > 0 ? 1 : 0);
  });

electionCommand
  .command('generate-ballot')
  .argument('<filename>', 'database file (.bel)')
  .requiredOption('--privcred <privcred>',  'private credentiel')
  .requiredOption('--choice <choice>',  'choice')
  .action(async function (filename, options) {
    try {
      const data = await fs.promises.readFile(filename);
      const tarReader = new TarReader(data);
      const files = tarReader.getFiles();
      const state = await check(files);
      const choice = JSON.parse(options.choice)
      const ballot = generateBallot(state, options.privcred, choice);
      const sBallot = JSON.stringify(canonicalBallot(ballot, state.setup.payload.election));
      console.log(sBallot);
    } catch (e) {
      console.error(e);
    }

    process.exit(errors > 0 ? 1 : 0);
  });

program.parseAsync(process.argv);
