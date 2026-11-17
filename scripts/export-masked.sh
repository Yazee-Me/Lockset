#!/bin/sh
# Read dotenv lines on stdin, mask every value in the job log, and append the
# lines to the file named by $1 (GitHub's $GITHUB_ENV). Used by the action:
#   lockset export --format dotenv | export-masked.sh "$GITHUB_ENV"
set -eu

target=${1:?usage: export-masked.sh <env-file>}

while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || continue
    case "$line" in
        *=*) ;;
        *) echo "not a dotenv line: $line" >&2; exit 1 ;;
    esac
    name=${line%%=*}
    value=${line#*=}
    [ -n "$name" ] || { echo "empty variable name" >&2; exit 1; }
    # A GitHub Actions workflow command: from here on the runner redacts the
    # value anywhere it would appear in the log. An empty value is not masked,
    # because masking nothing warns on GitHub.
    if [ -n "$value" ]; then
        printf '::add-mask::%s\n' "$value"
    fi
    printf '%s\n' "$line" >> "$target"
done
