#!/bin/bash

BASE_DIR=$PWD

for DIR in tests/imported/*; do
  if [ -d "$DIR" ]; then
    cd "$DIR"
    output=$(node -r ts-node/register ../../../src/cli/sirona.ts election verify)
    if [ $? -ne 0 ]; then
        echo "FAIL: $DIR"
    else
        echo "PASS: $DIR"
    fi
    cd $BASE_DIR
  fi
done
