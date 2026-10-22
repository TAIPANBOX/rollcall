#!/bin/sh
# Runs the teeth test: each gate must go red on its planted fault, pass on a
# clean copy, and report "measured nothing" when its subject is gone.
set -eu
cd "$(dirname "$0")/.."
exec go test ./internal/gates -run TestGatesHaveTeeth -v -count=1
