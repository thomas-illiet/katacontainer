#!/bin/sh
set -eu

output_dir=${COVERAGE_OUTPUT_DIR:-dist/coverage}
mkdir -p "$output_dir"
profile="$output_dir/coverage.out"

go test -covermode=atomic -coverprofile="$profile" ./internal/...
total=$(go tool cover -func="$profile" | awk '/^total:/ {gsub("%", "", $3); print $3}')

if [ "$total" != "100.0" ]; then
  echo "coverage check failed: expected 100.0%, got ${total}%" >&2
  go tool cover -func="$profile" >&2
  exit 1
fi

echo "coverage check passed: ${total}%"
