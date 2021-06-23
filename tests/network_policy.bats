#!/usr/bin/env bats

load utils/utils

function clean() {
    kubectl delete pods -n policy-test --all || true
    retry 30 3 object_not_exist pod -l app=policy-spod -n policy-test
    retry 30 3 object_not_exist pod -l app=non-policy-spod -n policy-test
    retry 30 3 object_not_exist pod -l app=non-policy-cli -n policy-test
    retry 30 3 object_not_exist pod -l app=policy-cli -n policy-test

    kubectl delete svc -n policy-test --all || true
    retry 30 3 object_not_exist svc -n policy-test

    kubectl delete networkpolicies -n policy-test --all || true
    retry 30 3 object_not_exist networkpolicies -n policy-test

    kubectl delete ns policy-test || true
	retry 30 3 object_not_exist ns policy-test
}

function setup() {
    clean
}

@test "test network policy" {
	kubectl apply -f templates/testcases/network_policy/policy.yaml
	retry 5 20 bash -c "kubectl get pod -n policy-test policy-cli | grep Completed"
    retry 5 20 bash -c "kubectl get pod -n policy-test non-policy-cli | grep Completed"
    result=`kubectl get pod -n policy-test -o jsonpath='{range .status.containerStatuses[*]}{.state.terminated.reason}{end}' policy-cli`
    [ "$result" = "CompletedCompleted" ]
    result=`kubectl get pod -n policy-test -o jsonpath='{range .status.containerStatuses[*]}{.state.terminated.reason}{end}' non-policy-cli`
    [ "$result" = "CompletedError" ]
    clean
}