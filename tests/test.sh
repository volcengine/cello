#!/bin/bash

set -e

# test cello pod ready 
bats cni_ready.bats

# test pod connection
bats pod_connection.bats

# test service of kinds of
bats service.bats

# test network policy
bats network_policy.bats
