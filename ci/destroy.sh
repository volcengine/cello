#!/usr/bin/env bash
set -e

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

if ! volcengine-cli -h &> /dev/null; then
  echo "volcengine-cli is not installed, please install it first."
  echo "See: https://github.com/volcengine/volcengine-cli"
  exit 1
fi

pushd $THIS_DIR/tf > /dev/null
# Remove secondary interfaces created by Cello
source example.tfvars
export VOLCENGINE_ACCESS_KEY="$access_key"
export VOLCENGINE_SECRET_KEY="$secret_key"
export VOLCENGINE_REGION=cn-bejing
vpc_id=$(terraform  show -json | jq -r '.values.root_module.resources[] | select(.address=="volcengine_vpc.vpc_cello") | .values.vpc_id')
interfaces=$(volcengine-cli vpc DescribeNetworkInterfaces --Type "secondary" --VpcId $vpc_id --TagFilters.1.Key "k8s:cello:created-by" --TagFilters.1.Values.1 "cello")
echo "$interfaces" | jq -r '.Result.NetworkInterfaceSets[].NetworkInterfaceId' | while read -r interface_id;
do
  instance_id=$(volcengine-cli vpc DescribeNetworkInterfaceAttributes --NetworkInterfaceId $interface_id | jq -r '.Result.DeviceId')
  set +e
  max_retries=10
  count=0
  if [ -n "$instance_id" ]; then
    while [ "$count" -lt "$max_retries" ]; do
        volcengine-cli vpc DetachNetworkInterface --NetworkInterfaceId $interface_id --InstanceId $instance_id
        if [ "$?" -eq "0" ]; then
          break
        fi
        count=$((counter+1))
        sleep 2
    done
    if [ "$count" -eq "$max_retries" ]; then
        exit 1
    fi
  fi
  # Retry multiple times since interface may at detaching status
  count=0
  while [ "$count" -lt "$max_retries" ]; do
    volcengine-cli vpc DeleteNetworkInterface --NetworkInterfaceId $interface_id
    if [ "$?" -eq "0" ]; then
      break
    fi
    count=$((counter+1))
    sleep 2
  done
  if [ "$count" -eq "$max_retries" ]; then
    exit 1
  fi
  set -e
done

terraform destroy -auto-approve -var-file=example.tfvars
popd > /dev/null
