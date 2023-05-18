#!/usr/bin/env bash
set -e

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
pushd $THIS_DIR > /dev/null
docker save -o /tmp/cello.tar volcstack/cello:latest

pushd playbook > /dev/null
ansible-playbook -i ../tf/hosts.yaml push_image.yaml
popd > /dev/null
popd > /dev/null
