#!/bin/bash

# Retry a command $1 times until it succeeds. Wait $2 seconds between retries.
function retry() {
	local attempts=$1
	local delay=$2
	local i

	for ((i=0; i < attempts; i++)); do
		run "${@:3}"
		if [[ "$status" -eq 0 ]] ; then
			return 0
		fi
		sleep $delay
	done

	echo "Command \"${@:3}\" failed $attempts times. Output: $output"
	false
}

# Repeat a command $1 times. Wait $2 seconds between retries.
function repeat() {
	local attempts=$1
	local delay=$2
	local i

	for ((i=0; i < attempts; i++)); do
		run "${@:3}"
		if [[ "$status" -ne 0 ]] ; then
			return false
		fi
		sleep $delay
	done
	return 0
}

function object_not_exist() {
	run kubectl get $@
	if [[ "$status" -gt 0 ]] || [[ ${#lines[@]} -eq 1 ]]; then
		return 0
	fi
	echo "object $@ exist, status: $status, lines: ${#lines[@]} output $output"
	false
}

function object_exist() {
	run kubectl get $@
	if [[ "$status" -eq 0 ]] && [[ ${#lines[@]} -gt 1 ]]; then
		return 0
	fi
	echo "object $@ not ready, status: $status, lines: ${#lines[@]} output $output"
	false
}


function pod_running() {
	run kubectl get $@
	if [[ "$status" -eq 0 ]] && [[ ${#lines[@]} -gt 1 ]] && echo $output | grep -q "Running"; then
		return 0
	fi
	echo "object $@ not ready, status: $status, lines: ${#lines[@]} output $output"
	false
}


function svc_ready() {
	run kubectl get $@
	if [[ "$status" -eq 0 ]] && [[ ${#lines[@]} -gt 1 ]]; then
		if echo $output | grep -q "pending"; then
			false
			echo "object $@ pending, status: $status, lines: ${#lines[@]} output $output"
			return 1
		fi
		return 0
	fi
	echo "object $@ exist, status: $status, lines: ${#lines[@]} output $output"
	false
}