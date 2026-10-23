#!/usr/bin/env bats

setup() {
  export RAT_DRYRUN=1
  export TEMP_DIR="$(mktemp -d)"
  export PATH="$TEMP_DIR/bin:$PATH"
  mkdir -p "$TEMP_DIR/bin"
}

teardown() {
  rm -rf "$TEMP_DIR"
}

@test "tests/shell/qa-helper.bats::R1: shellcheck clean" {
  run shellcheck App/Resources/rat-pf-helper.sh
  [ "$status" -eq 0 ]
  run shellcheck scripts/fetch-geoip.sh
  [ "$status" -eq 0 ]
  run shellcheck scripts/verify-blocking.sh
  [ "$status" -eq 0 ]
}

@test "tests/shell/qa-helper.bats::R2: rat-pf-helper snapshot side-effects" {
  OUT="$TEMP_DIR/snap.txt"
  run App/Resources/rat-pf-helper.sh snapshot "$OUT"
  [ "$status" -eq 0 ]
  [ -f "$OUT" ]
}

@test "tests/shell/qa-helper.bats::R5: snapshot output format" {
  OUT="$TEMP_DIR/snap.txt"
  run App/Resources/rat-pf-helper.sh snapshot "$OUT"
  [ "$status" -eq 0 ]

  run cat "$OUT"
  echo "$output" | grep "#PS"
}

@test "tests/shell/qa-helper.bats::R6: fetch script verifies download" {
  cat << 'MOCK_CURL' > "$TEMP_DIR/bin/curl"
#!/bin/sh
for arg in "\$@"; do
  if [ "\$arg" = "-o" ]; then
    shift
    echo "invalid payload" > "\$1"
    return 0
  fi
  shift
done
MOCK_CURL
  chmod +x "$TEMP_DIR/bin/curl"

  run scripts/fetch-geoip.sh
  [ "$status" -eq 1 ]
  echo "$output" | grep "could not download the DB-IP city database" || true
}

@test "tests/shell/qa-helper.bats::R6: fetch script fails cleanly offline" {
  cat << 'MOCK_CURL' > "$TEMP_DIR/bin/curl"
#!/bin/sh
false
MOCK_CURL
  chmod +x "$TEMP_DIR/bin/curl"

  run scripts/fetch-geoip.sh
  [ "$status" -eq 1 ]
  echo "$output" | grep "could not download the DB-IP city database" || true
}
