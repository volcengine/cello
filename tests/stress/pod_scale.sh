#!/usr/bin/env bash

source ../utils/utils.bash

stress_ns=stress-scale
deploymet_yaml=../templates/testcases/stress/scale.yaml
max_scale=20
total=10
test_succeed=0
test_count=0

trap 'teardown' 2

setup_env() {
    kubectl apply -f ${deploymet_yaml}
}

teardown() {
    kubectl delete -f ${deploymet_yaml}
    echo tested $test_count, succeed $test_succeed
    exit
}

scale_period=60 #secs
scale_jitter=30 #secs
test_scale() {
	deploy=$1
	scale_num=$((RANDOM%max_scale))
    echo "scale dep to $scale_num"
	kubectl -n ${stress_ns} scale --replicas ${scale_num} deploy "${deploy}"
	jitter_time=$((RANDOM%(scale_jitter*2)-scale_jitter))
	sleep $((scale_period+jitter_time))
    running=`kubectl get pods -A -owide |grep nginx-deployment |grep Running |wc -l`
    pending=`kubectl get pods -A -owide |grep nginx-deployment |grep Pending |wc -l`
    terminat=`kubectl get pods -A -owide |grep nginx-deployment |grep Terminating |wc -l`
    creating=`kubectl get pods -A -owide |grep nginx-deployment |grep ContainerCreating |wc -l`
    echo "running: $running pending: $pending terminat: $terminat creating: $creating"
    if [ $scale_num -ne $running ]; then
        sleep $((scale_period+jitter_time))
    fi
    running=`kubectl get pods -A -owide |grep nginx-deployment |grep Running |wc -l`
    ((test_count++))
    if [ $scale_num -ne $running ]; then
        return
    fi
    ((test_succeed++))
}

setup_env
for (( i=0; i<total; i++)); do
  test_scale nginx-deployment
done

teardown

