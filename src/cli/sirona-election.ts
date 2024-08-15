import fs from "fs";
import { execSync } from "child_process";
import { Command } from "commander";
import * as Archive from "../Archive";
import generateBallot from "../generateBallot";
import canonicalBallot from "../canonicalBallot";
import { getLogs, getBallotLogs } from "../logger";
import check from "../check";

const program = new Command();

program
  .command("verify")
  .option("--uuid <UUID>", "database file (.bel)")
  .option("--url <URL>", "Download election files from URL")
  .option("-q, --quiet", "only show the final result")
  .action(async function (options) {
    const checkFile = async (filePath) => {
      const files = await Archive.readFile(filePath);
      const state = await check(files);
      const election = state.setup.payload.election;

      console.log("Election fingerprint: " + election.fingerprint);
      console.log(state.files.length + " files found.");
      for (let i = 0; i < state.setup.payload.election.questions.length; i++) {
        let question = state.setup.payload.election.questions[i];
        let questionType = question.type ? question.type : "Homomorphic";
        console.log(`Question ${i + 1} (${questionType})`);
      }
      console.log(state.ballots.length + " ballots found.");

      const sectionLogs = getLogs();
      const sections = Object.keys(sectionLogs);
      for (let i = 0; i < sections.length; i++) {
        const logs = sectionLogs[sections[i]];
        if (!options.quiet) console.log("=== " + sections[i] + " ===");
        for (let j = 0; j < logs.length; j++) {
          if (!logs[j].pass) {
            errors++;
          }
          const prefix = logs[j].pass ? "✅" : "❌";
          if (!options.quiet) console.log(prefix + logs[j].message);
        }
      }

      const ballotLogs = getBallotLogs();
      const ballotKeys = Object.keys(ballotLogs);
      if (!options.quiet) console.log("=== BALLOTS ===");
      for (let i = 0; i < ballotKeys.length; i++) {
        const logs = ballotLogs[ballotKeys[i]];
        if (!options.quiet) console.log("=== " + ballotKeys[i] + " ===");
        for (let j = 0; j < logs.length; j++) {
          if (!logs[j].pass) {
            errors++;
          }
          const prefix = logs[j].pass ? "✅" : "❌";
          if (!options.quiet) console.log(prefix + logs[j].message);
        }
      }
    };

    let uuid = options.uuid
    if (options.url) {
      let baseUrl = "";
      const path = options.url.split("/");
      if (path[path.length - 1] === "") {
        path.pop();
      }
      const last = path[path.length - 1];
      if (last.split(".").length === 2 && last.split(".")[1] === "bel") {
        baseUrl = path.slice(0, -1).join("/");
        uuid = last.split(".")[0];
      } else {
        baseUrl = path.join("/");
        uuid = last
      }

      console.log(`Downloading ${baseUrl}/${uuid}.bel...`);
      execSync(`wget -r -np -nH -nd -P . ${baseUrl}/${uuid}.bel`);
    }

    console.log(`Checking ${uuid}.bel...`);
    await checkFile(uuid + ".bel");
    console.log(`${errors} errors found.`);

    process.exit(errors > 0 ? 1 : 0);
  });

let errors = 0;

program
  .command("generate-ballot")
  .argument("<filename>", "database file (.bel)")
  .requiredOption("--privcred <privcred>", "private credentiel")
  .requiredOption("--choice <choice>", "choice")
  .action(async function (filename, options) {
    try {
      const files = await Archive.readFile(filename);
      const state = await check(files);
      const choice = JSON.parse(options.choice);
      const ballot = generateBallot(state, options.privcred, choice);
      const sBallot = JSON.stringify(
        canonicalBallot(ballot, state.setup.payload.election),
      );
      console.log(sBallot);
    } catch (e) {
      console.error(e);
    }

    process.exit(errors > 0 ? 1 : 0);
  });

program.parseAsync(process.argv);
