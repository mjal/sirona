#!/bin/bash

set -e

ROOT_DIR=$PWD

sirona () {
    node -r ts-node/register $ROOT_DIR/src/cli/sirona.ts -- "$@"
}

header () {
    echo
    echo "=-=-= $1 =-=-="
    echo
}

header "Setup election"

UUID=`sirona setup generate-token`
echo "UUID of the election is $UUID"

DIR=tests/tool/data/$UUID
mkdir -p $DIR
cd $DIR

echo -n "" > public_keys.json

sirona setup generate-trustee-key
cat pubkey >> public_keys.jsons
echo "" >> public_keys.jsons

sirona setup generate-trustee-key
cat pubkey >> public_keys.jsons
echo "" >> public_keys.jsons

sirona setup generate-trustee-key
cat pubkey >> public_keys.jsons
echo "" >> public_keys.jsons

sirona setup make-trustees

sirona setup make-election $UUID --template $ROOT_DIR/tests/tool/templates/questions.json
