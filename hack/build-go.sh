#!/usr/bin/env bash

set -eu

make build GO_BUILD_FLAGS="-gcflags \"all=-N -l\""
