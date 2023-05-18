#!/usr/bin/env bash
set -e

extra_args=""
if [ -n "$TF_PLUGIN_DIR" ]; then
  extra_args="$extra_args -plugin-dir $TF_PLUGIN_DIR"
fi

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
pushd $THIS_DIR > /dev/null

pushd tf > /dev/null
terraform init $extra_args
terraform apply -auto-approve -var-file=example.tfvars
popd > /dev/null

pushd playbook > /dev/null
ansible-playbook -i ../tf/hosts.yaml k8s.yaml
popd > /dev/null
