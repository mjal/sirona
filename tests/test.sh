#!/bin/bash

check_errors() {
    local f="$1"
    local output

    output=$(node -r ts-node/register src/cli/sirona.ts election verify $f)

    if echo "$output" | grep -q "0 errors found."; then
        echo "PASS: $f"
    else
        echo "FAIL: $f"
    fi
}

# Loop through each .bel files in tests and check for errors
for f in tests/*.bel; do
    check_errors "$f"
done
