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

# Generate credentials
cat > voters.txt <<EOF
voter1@example.com,voter1,1000000000
voter2@example.com,voter2,2000000000
voter3@example.com,voter3,3000000000
voter4@example.com,voter4,4000000000
voter5@example.com,voter5,90000000000
EOF
sirona setup generate-credentials --uuid $UUID --file voters.txt | tee generate-credentials.out
mv *.pubcreds public_creds.json
mv *.privcreds private_creds.json
paste <(jq --raw-output 'keys_unsorted[]' < private_creds.json) <(jq --raw-output '.[]' < private_creds.json) > private_creds.txt

# Generate trustee keys
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
