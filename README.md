# Sirona 🎑

## An external tool to interact with Belenios elections

## Install

`npm install`

## Usage (web)

`npm run dev`

## Usage (cli)

`npm run cli`

Two commands implemented:

`ts-node src/cli.ts election verify`

`ts-node src/cli.ts election generate-ballot`

## Features

Only focus on a subset of Belenios specification.

For exemple, we only support the ed25519 group.

Roadmap:

- [x] A.1.1 Verify homomorpic questions without blank vote
- [x] A.1.2 Verify homomorpic questions with blank vote

- [x] A.2.1 Generate Homomorpic questions without blank vote
- [x] A.2.2 Generate Homomorpic questions with blank vote

- [x] C.1 Verify "Lists" questions
- [ ] C.2 Generate "List" questions

- [ ] B.1 Verify shuffleds questions
- [ ] B.2 Generate shuffleds questions

- [x] T.1 Pedersen trustees
