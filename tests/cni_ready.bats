#!/usr/bin/env bats

load utils/utils

@test "cello ds ready test" {
	cello_ready_count="$(kubectl get ds cello -n kube-system -o jsonpath='{.status.numberReady}')"
	node_count="$(kubectl get node -o name |grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' |wc -l)"
	echo $cello_ready_count " " $node_count
	[ "$cello_ready_count" -eq "$node_count" ]
}