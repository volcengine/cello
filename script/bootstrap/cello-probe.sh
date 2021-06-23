#!/bin/bash

function retry() {
	local attempts=$1
	local delay=$2
	local i

	for ((i=0; i < attempts; i++)); do
		"${@:3}"
		# shellcheck disable=SC2181
		if [[ $? -eq 0 ]] ; then
            # shellcheck disable=SC2145
            echo "Command \"${@:3}\" success $i times."
			return 0
		fi
		sleep "$delay"
	done

	# shellcheck disable=SC2145
	echo "Command \"${@:3}\" failed $attempts times."
	false
}

function probe_cello_ready() {
    # shellcheck disable=SC2006
    result=`curl -s --unix-socket /var/run/cello/cello_debug.socket http://localhost/ |grep ok`
    if [[ "$result" != "" ]]
    then
        return 0
    else
        return 1
    fi
}

retry 30 2 probe_cello_ready
