#!/usr/bin/env bash
# Copyright 2023 The Cello Authors

set -x

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
TEST_OUTPUT=$THIS_DIR/"output"
SONOBUOY_VRSION="v0.56.16"
SONOBUOY="go run github.com/vmware-tanzu/sonobuoy@$SONOBUOY_VRSION"


DEFAULT_E2E_SIG_NETWORK_CONFORMANCE="\[sig-network\].*Conformance"
DEFAULT_E2E_SIG_NETWORK_SKIP="\[Slow\]|\[Serial\]|\[Disruptive\]|\[GCE\]|\[Feature:.+\]|\[Feature:IPv6DualStack\]|\[Feature:IPv6DualStackAlphaFeature\]|should create pod that uses dns|should provide Internet connection for containers|\
HostPort validates that there is no conflict between pods with same hostPort but different hostIP and protocol"

extra_args=""
if [ -n "$SONOBUOY_IMAGE" ]; then
  extra_args="$extra_args --sonobuoy-image $SONOBUOY_IMAGE"
fi
if [ -n "$CONFORMANCE_IMAGE" ]; then
  extra_args="$extra_args --kube-conformance-image $CONFORMANCE_IMAGE"
fi
if [ -n $SYSTEMD_LOGS_IMAGE ]; then
  extra_args="$extra_args --systemd-logs-image $SYSTEMD_LOGS_IMAGE"
fi
if [ -n $E2E_REPO_CONFIG ]; then
  extra_args="$extra_args --e2e-repo-config $E2E_REPO_CONFIG"
fi
pushd $THIS_DIR > /dev/null
$SONOBUOY run \
    --wait \
    --e2e-focus "$DEFAULT_E2E_SIG_NETWORK_CONFORMANCE" \
    --e2e-skip "$DEFAULT_E2E_SIG_NETWORK_SKIP" \
    $extra_args

mkdir -f $TEST_OUTPUT
results_path=$($SONOBUOY retrieve $TEST_OUTPUT)
results=$($SONOBUOY results $results_path --plugin e2e)
echo "$results" > $TEST_OUTPUT/test_summary.log
echo "$($SONOBUOY results $results_path --plugin e2e --mode=detailed | jq 'select(.status=="passed" or .status=="failed)')" > $TEST_OUTPUT/tests.log
echo "$($SONOBUOY results $results_path --plugin e2e --mode=detailed | jq 'select(.status=="passed")')" > $TEST_OUTPUT/passed_tests.log
echo "$($SONOBUOY results $results_path --plugin e2e --mode=detailed | jq 'select(.status=="failed")')" > $TEST_OUTPUT/failed_tests.log
echo "$($SONOBUOY results $results_path --plugin e2e --mode=detailed | jq 'select(.status=="skipped")')" > $TEST_OUTPUT/skpped_tests.log
if [[ ! $results == *"Failed: 0"* ]]; then
  echo "Test failed!"
  exit 1
fi
echo "Test successfully!"
exit 0
