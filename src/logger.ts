let logs = {};
let ballotLogs = {};

export function log(section: string, pass: boolean, message: string) {
  if (!logs[section]) {
    logs[section] = [];
  }
  logs[section].push({ pass, message });
}

export function logBallot(ballotId: string, pass: boolean, message: string) {
  if (!ballotLogs[ballotId]) {
    ballotLogs[ballotId] = [];
  }
  ballotLogs[ballotId].push({ pass, message });
}

export function getLogs() {
  return logs;
}
export function getBallotLogs() {
  return ballotLogs;
}
