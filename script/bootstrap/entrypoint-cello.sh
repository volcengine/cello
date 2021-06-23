#!/usr/bin/env bash

CURDIR=$(
  cd $(dirname $0) || exit
  pwd
)

cd "${CURDIR}" || exit
cd /cello  || exit
./cello-agent
