#!/usr/bin/env bats

load utils/utils

function test_check_clean() {
    kubectl delete -f templates/testcases/cilium_network_policy/check.yaml || true
    retry 10 2 object_not_exist pod -l role=test-check -n test-check
    sleep 2
}

function test_pre_check_external_svc() {
    kubectl apply -f templates/testcases/cilium_network_policy/check.yaml || true
    retry 20 2 object_exist pod -l role=test-check -n test-check

    check_pod=`kubectl get pod -l role=test-check -n test-check -o wide |awk 'NR!=1 {print $1}'`
    run kubectl -n test-check exec -it $check_pod -- ping -c 2 $1
    if [[ "$status" -eq 0 ]]; then
        return 0
    fi
    echo "external_svc $@ not exist, status: $status, lines: ${#lines[@]} output: $output"
    return false
}

function teardown() {
    test_check_clean
    l3_label_clean
    l3_label_additional_require_clean
    l3_service_clean
    l3_identify_clean
    l3_cidr_clean
    l4_port_clean
    l4_labels_dependent_clean
    l4_cidr_dependent_clean
    deny_rule_clean
}

function l3_label_clean() {
    kubectl delete -f templates/testcases/cilium_network_policy/l3_label.yaml || true
    retry 20 2 object_not_exist pod -l case=l3-rule-label -n cilium-policy-l3-label
    sleep 2
}

function l3_label_setup() {
    kubectl apply -f templates/testcases/cilium_network_policy/l3_label.yaml || true
}

@test "l3_label" {
    l3_label_clean
    l3_label_setup
    retry 5 5 kubectl apply -f templates/testcases/cilium_network_policy/l3_label.yaml
    retry 20 5 object_exist pod -l role=l3-rule-label-server -n cilium-policy-l3-label
    retry 20 5 object_exist pod -l role=l3-rule-label-client1 -n cilium-policy-l3-label
    retry 20 5 object_exist pod -l role=l3-rule-label-client2 -n cilium-policy-l3-label
    sleep 10

    server=`kubectl get pod -l role=l3-rule-label-server -n cilium-policy-l3-label -o wide |awk 'NR!=1 {print $6}'`
    client1_pod=`kubectl get pod -l role=l3-rule-label-client1 -n cilium-policy-l3-label -o wide |awk 'NR!=1 {print $1}'`
    run kubectl -n cilium-policy-l3-label exec -it $client1_pod -- ping -c 2 $server
    [ "$status" -eq 0 ]

    client2_pod=`kubectl get pod -l role=l3-rule-label-client2 -n cilium-policy-l3-label -o wide |awk 'NR!=1 {print $1}'`
    run kubectl -n cilium-policy-l3-label exec -it $client2_pod -- ping -c 2 $server
    [ "$status" -eq 1 ]

    retry 20 5 object_exist pod -l role=l3-rule-label-src -n cilium-policy-l3-label
    retry 20 5 object_exist pod -l role=l3-rule-label-dst -n cilium-policy-l3-label
    src_ip=`kubectl get pod -l role=l3-rule-label-src -n cilium-policy-l3-label -o wide |awk 'NR!=1 {print $6}'`
    dst_ip=`kubectl get pod -l role=l3-rule-label-dst -n cilium-policy-l3-label -o wide |awk 'NR!=1 {print $6}'`
    src_pod=`kubectl get pod -l role=l3-rule-label-src -n cilium-policy-l3-label -o wide |awk 'NR!=1 {print $1}'`
    dst_pod=`kubectl get pod -l role=l3-rule-label-dst -n cilium-policy-l3-label -o wide |awk 'NR!=1 {print $1}'`

    run kubectl -n cilium-policy-l3-label exec -it $src_pod -- ping -c 2 $dst_ip
    [ "$status" -eq 1 ]

    run kubectl -n cilium-policy-l3-label exec -it $dst_pod -- ping -c 2 $src_ip
    [ "$status" -eq 0 ]

    l3_label_clean
}

function l3_label_additional_require_clean() {
    kubectl delete -f templates/testcases/cilium_network_policy/l3_label_additional_require.yaml || true
    retry 30 2 object_not_exist pod -l case=l3-label-add-req -n cilium-policy-l3-label-add-req
    sleep 2
}

@test "l3_label_additional_require" {
    l3_label_additional_require_clean
    kubectl apply -f templates/testcases/cilium_network_policy/l3_label_additional_require.yaml || true
    retry 20 2 pod_running pod l3-label-add-req-prod-front -n cilium-policy-l3-label-add-req
    retry 20 2 pod_running pod l3-label-add-req-prod-backend -n cilium-policy-l3-label-add-req
    retry 20 2 pod_running pod l3-label-add-req-test -n cilium-policy-l3-label-add-req
    backend_ip=`kubectl get pod l3-label-add-req-prod-backend -n cilium-policy-l3-label-add-req -o wide |awk 'NR!=1 {print $6}'`

    run kubectl exec -it l3-label-add-req-prod-front -n cilium-policy-l3-label-add-req -- ping -c 2 $backend_ip
    [ "$status" -eq 0 ]

    run kubectl exec -it l3-label-add-req-test -n cilium-policy-l3-label-add-req -- ping -c 2 $backend_ip
    [ "$status" -eq 1 ]

    l3_label_additional_require_clean
}

function l3_service_clean() {
    kubectl delete pod -l case=l3-rule-service -n cilium-policy-l3-label || true
    kubectl delete -f templates/testcases/cilium_network_policy/l3_service_stage3.yaml || true
    kubectl delete -f templates/testcases/cilium_network_policy/l3_service_stage1.yaml || true
    retry 20 2 object_not_exist pod -l case=l3-rule-service -n cilium-policy-l3-label
    sleep 2
}

@test "l3_service" {
    l3_service_clean

    kubectl apply -f templates/testcases/cilium_network_policy/l3_service_stage1.yaml || true
    sleep 5
    node_count=`kubectl get nodes |grep Ready | awk '{print $1}' |grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | wc -l`
    [ "$node_count" -ge 2 ]

    backend0_ip=`kubectl get nodes |grep Ready | awk '{print $1}' |grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' |awk 'NR==1 {print $1}'`
    backend1_ip=`kubectl get nodes |grep Ready | awk '{print $1}' |grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' |awk 'NR==2 {print $1}'`

    cat templates/testcases/cilium_network_policy/l3_service_stage2.yaml | sed 's/BACKEND_IP_0/'"${backend0_ip}"'/g' | sed 's/BACKEND_IP_1/'"${backend1_ip}"'/g' | kubectl apply -f -

    kubectl apply -f templates/testcases/cilium_network_policy/l3_service_stage3.yaml || true

    retry 10 10 bash -c "kubectl get pod -n cilium-policy-l3-service l3-service-client | grep -E 'Completed | Error'"
    result=`kubectl get pod -n cilium-policy-l3-service -o jsonpath='{range .status.containerStatuses[*]}{.state.terminated.reason}{end}' l3-service-client`
    [ "$result" = "ErrorCompleted" ]

    l3_service_clean
}

function l3_identify_clean() {
    kubectl delete -f templates/testcases/cilium_network_policy/l3_identify.yaml || true
    retry 20 2 object_not_exist pod -l case=l3-rule-identify -n cilium-policy-l3-identify
    sleep 2
}

function l3_identify_setup() {
    kubectl apply -f templates/testcases/cilium_network_policy/l3_identify.yaml || true
    retry 20 2 object_exist pod -l case=l3-rule-identify -n cilium-policy-l3-identify
    sleep 2
}

@test "l3_identify" {
    run test_pre_check_external_svc 100.96.0.96
    if [ "$status" -eq 0 ]; then
            skip
    fi

    l3_identify_clean
    l3_identify_setup

    retry 10 10 bash -c "kubectl get pod -n cilium-policy-l3-identify -l case=l3-rule-identify | grep -E 'Completed | Error'"
    result=`kubectl get pod -n cilium-policy-l3-identify -o jsonpath='{range .status.containerStatuses[*]}{.state.terminated.reason}{end}' l3-rule-identify-source`
    [ "$result" = "ErrorCompleted" ]

    l3_identify_clean
}

function l3_cidr_clean() {
    kubectl delete -f templates/testcases/cilium_network_policy/l3_cidr.yaml || true
    sleep 2
}

@test "l3_cidr" {
    run test_pre_check_external_svc 100.96.0.96
    if [ "$status" -eq 0 ]; then
        skip
    fi

    l3_cidr_clean
    kubectl apply -f templates/testcases/cilium_network_policy/l3_cidr.yaml || true
    sleep 5

    retry 10 10 bash -c "kubectl get pod -n cilium-policy-l3-cidr -l case=l3-rule-cidr | grep -E 'Completed | Error'"
    result=`kubectl get pod -n cilium-policy-l3-cidr -o jsonpath='{range .status.containerStatuses[*]}{.state.terminated.reason}{end}' l3-rule-cidr-source`
    [ "$result" = "ErrorCompleted" ]

    l3_cidr_clean
}

function l4_port_clean() {
    kubectl delete -f templates/testcases/cilium_network_policy/l4_port.yaml || true
    sleep 2
}

@test "l4_port" {
    run test_pre_check_external_svc 100.96.0.96
    if [ "$status" -eq 0 ]; then
        skip
    fi

    l4_port_clean
    kubectl apply -f templates/testcases/cilium_network_policy/l4_port.yaml || true
    sleep 5

    retry 10 10 bash -c "kubectl get pod -n cilium-policy-l4-port -l case=l4-rule-port | grep -E 'Completed | Error'"
    result=`kubectl get pod -n cilium-policy-l4-port -o jsonpath='{range .status.containerStatuses[*]}{.state.terminated.reason}{end}' l4-rule-port-source`
    [ "$result" = "ErrorCompleted" ]

    l4_port_clean
}

function l4_labels_dependent_clean() {
    kubectl delete -f templates/testcases/cilium_network_policy/l4_labels_dependent.yaml || true
    sleep 2
}

@test "l4_labels_dependent" {
    l4_labels_dependent_clean
    kubectl apply -f templates/testcases/cilium_network_policy/l4_labels_dependent.yaml || true
    retry 20 2 object_exist pod -l case=l4-label-dep -n cilium-policy-l4-label-dep
    sleep 10

    retry 10 10 bash -c "kubectl get pod -n cilium-policy-l4-label-dep -l case=l4-label-dep | grep -E 'Completed | Error'"
    result=`kubectl get pod -n cilium-policy-l4-label-dep -o jsonpath='{range .status.containerStatuses[*]}{.state.terminated.reason}{end}' l4-label-dep-source`
    [ "$result" = "ErrorCompleted" ]

    l4_labels_dependent_clean
}

function l4_cidr_dependent_clean() {
    kubectl delete -f templates/testcases/cilium_network_policy/l4_cidr_dependent_stage1.yaml || true
    kubectl delete -f templates/testcases/cilium_network_policy/l4_cidr_dependent_stage2.yaml || true
    retry 20 2 object_not_exist pod -l case=l4-cidr-dep -n cilium-policy-l4-cidr-dep
    sleep 2
}

@test "l4_cidr_dependent" {
    run test_pre_check_external_svc 100.96.0.96
    if [ "$status" -eq 0 ]; then
        skip
    fi

    l4_cidr_dependent_clean

    kubectl apply -f templates/testcases/cilium_network_policy/l4_cidr_dependent_stage1.yaml || true
    retry 10 10 bash -c "kubectl get pod -n cilium-policy-l4-cidr-dep -l case=l4-cidr-dep | grep -E 'Completed | Error'"
    result=`kubectl get pod -n cilium-policy-l4-cidr-dep -o jsonpath='{range .status.containerStatuses[*]}{.state.terminated.reason}{end}' l4-cidr-dep-source1`
    [ "$result" = "Error" ]
    kubectl delete -f templates/testcases/cilium_network_policy/l4_cidr_dependent_stage1.yaml || true
    retry 20 2 object_not_exist pod -l case=l4-cidr-dep -n cilium-policy-l4-cidr-dep

    kubectl apply -f templates/testcases/cilium_network_policy/l4_cidr_dependent_stage2.yaml || true
    retry 10 10 bash -c "kubectl get pod -n cilium-policy-l4-cidr-dep -l case=l4-cidr-dep | grep -E 'Completed | Error'"
    result=`kubectl get pod -n cilium-policy-l4-cidr-dep -o jsonpath='{range .status.containerStatuses[*]}{.state.terminated.reason}{end}' l4-cidr-dep-source2`
    [ "$result" = "Completed" ]

    l4_cidr_dependent_clean
}

function deny_rule_clean() {
    kubectl delete -f templates/testcases/cilium_network_policy/deny.yaml || true
    retry 30 2 object_not_exist pod -l case=deny-rule -n cilium-policy-deny
    sleep 2
}

@test "deny_rule" {
    deny_rule_clean
    kubectl apply -f templates/testcases/cilium_network_policy/deny.yaml || true
    retry 20 2 pod_running pod deny-rule-prod-front -n cilium-policy-deny
    retry 20 2 pod_running pod deny-rule-prod-backend -n cilium-policy-deny
    retry 20 2 pod_running pod deny-rule-prod-test -n cilium-policy-deny
    backend_ip=`kubectl get pod deny-rule-prod-backend -n cilium-policy-deny -o wide |awk 'NR!=1 {print $6}'`

    run kubectl exec -it deny-rule-prod-front -n cilium-policy-deny -- ping -c 2 $backend_ip
    [ "$status" -eq 0 ]

    run kubectl exec -it deny-rule-prod-test -n cilium-policy-deny -- ping -c 2 $backend_ip
    [ "$status" -eq 1 ]

    deny_rule_clean
}
