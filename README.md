# Sirona (yet another tool for Belenios elections) 🎑

## Disclaimer

Experimental. Implement a subset of belenios protocol 2.5.0. Only support ed25519.

## Without install

`npx sirona election verify --url https://vote.server.org/elections/MyElectionUuid`

## Install

`yarn`

## Usage (web)

`yarn run dev`

ou

`yarn run build`

TODO: Add screenshots

## Usage (cli)

`yarn run cli -- COMMAND [ARGS]`

### Supported commands

- setup generate-token
- setup generate-credentials
- election verify
- election generate-ballot
- archive add-event
- sha256-b64

## Features

- [x] A.1.1 Verify homomorpic questions without blank vote
- [x] A.1.2 Verify homomorpic questions with blank vote

- [x] A.2.1 Generate Homomorpic questions without blank vote
- [x] A.2.2 Generate Homomorpic questions with blank vote

- [x] C.1 Verify "Lists" questions
- [ ] C.2 Generate "List" questions

- [x] B.1 Verify shuffleds questions
- [ ] B.2 Generate shuffleds questions

- [x] T.1 Pedersen trustees
