#!/usr/bin/env bash

set -e
set -x

CURDIR=$(
  cd $(dirname $0) || exit
  pwd
)

cd "${CURDIR}" || exit

# install CNIs
/bin/cp -f /etc/cello/net.d/* /etc/cni/net.d
/bin/cp -f /cello/cello-cni /opt/cni/bin
/bin/cp -f /containernetworking/plugins/* /opt/cni/bin/
