#!/usr/bin/env node

import { promises as fs } from "fs";
import { execSync } from "child_process";
import { Command } from "commander";
import * as Archive from "../Archive";
import * as Ballot from "../Ballot";
import * as Election from "../Election";
import generateBallot from "../generateBallot";
import check from "../check";

const program = new Command();

program
  .command("verify")
  .option("--url <URL>", "Download election files from URL")
  .option("-q, --quiet", "only show the final result")
  .action(async function (options) {
    const checkFile = async (filePath) => {
      const files = await Archive.readFile(filePath);
      const state = await check(files);
      const election = state.setup.election;

      console.log("Election fingerprint: " + Election.fingerprint(election));
      for (let i = 0; i < state.setup.election.questions.length; i++) {
        let question = state.setup.election.questions[i];
        let questionType = question.type ? question.type : "Homomorphic";
        console.log(`Question ${i + 1} (${questionType})`);
      }
      console.log(state.ballots.length + " ballots found.");
    };

    let uuid = options.uuid;
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
        uuid = last;
      }

      console.log(`Downloading ${baseUrl}/${uuid}.bel...`);
      execSync(`wget -r -np -nH -nd -P . ${baseUrl}/${uuid}.bel`);
    }

    const dirFiles = await fs.readdir(".");
    const belFile = dirFiles.find(file => file.endsWith('.bel'));
    if (!belFile) {
      throw new Error('No .bel files found');
    }

    console.log(`Checking ${belFile}...`);
    await checkFile(belFile);
  });

program
  .command("generate-ballot")
  .requiredOption("--privcred <privcred>", "private credentiel")
  .requiredOption("--choice <choice>", "choice")
  .action(async function (options) {
    const dirFiles = await fs.readdir(".");
    const belFile = dirFiles.find(file => file.endsWith('.bel'));
    if (!belFile) {
      throw new Error('No .bel files found');
    }
    const files = await Archive.readFile(belFile);
    const state = await check(files);
    const choiceFile = await fs.readFile(options.choice);
    const choice = JSON.parse(choiceFile.toString());

    const privcredFile = await fs.readFile(options.privcred);
    const privcred = privcredFile.toString().trim();

    const ballot = generateBallot(state, privcred, choice);
    const sBallot = JSON.stringify(
      Ballot.toJSON(ballot, state.setup.election),
      null,
      0
    );
    console.log(sBallot);
  });

program.parseAsync(process.argv);
