import { log } from "./logger";
import { TarReader } from "./tarReader.js";
import check from "./check.js";
import fs from 'node:fs'
import { getLogs, getBallotLogs } from "./logger";

const filePath = Deno.args[0];

const data = await fs.promises.readFile(filePath);

const tarReader = new TarReader(data);
const files = tarReader.getFiles();
const state = await check(files);
let errors = 0;

const sectionLogs = getLogs();
const sections = Object.keys(sectionLogs);
for (let i = 0; i < sections.length; i++) {
  const logs = sectionLogs[sections[i]];
  console.log("=== " + sections[i] + " ===");
  for (let j = 0; j < logs.length; j++) {
    if (!logs[j].pass) { errors++; }
    const prefix = logs[j].pass ? "✅" : "❌";
    console.log(prefix + logs[j].message);
  }
}

const ballotLogs = getBallotLogs();
const ballotKeys = Object.keys(ballotLogs);
console.log("=== BALLOTS ===");
for (let i = 0; i < ballotKeys.length; i++) {
  const logs = ballotLogs[ballotKeys[i]];
  console.log("=== " + ballotKeys[i] + " ===");
  for (let j = 0; j < logs.length; j++) {
    if (!logs[j].pass) { errors++; }
    const prefix = logs[j].pass ? "✅" : "❌";
    console.log(prefix + logs[j].message);
  }
}

Deno.exit(errors > 0 ? 1 : 0);
