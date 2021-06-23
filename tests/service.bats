#!/usr/bin/env bats

load utils/utils

function delete_deploy() {
	retry 20 2 object_not_exist pod -l app=nodeport-nginx
    retry 20 2 object_not_exist pod -l app=nodeport-nginx-hn
	retry 20 2 object_not_exist pod -l app=clusterip-nginx
    retry 20 2 object_not_exist pod -l app=clusterip-nginx-hn
    retry 20 2 object_not_exist svc nodeport-service
    retry 20 2 object_not_exist svc nodeport-service-hn
    retry 20 2 object_not_exist svc clusterip-service
    retry 20 2 object_not_exist svc clusterip-service-hn
    retry 20 2 object_not_exist pod -l app=nodeport-tool
    retry 20 2 object_not_exist pod -l app=nodeport-tool-hn
    retry 20 2 object_not_exist pod -l app=clusterip-tool
    retry 20 2 object_not_exist pod -l app=clusterip-tool-hn
    retry 20 2 object_not_exist pod -l app=spod
    retry 20 2 object_not_exist svc -l test=lbsvc
    retry 20 2 object_not_exist pod -l app=spod-hn
    retry 20 2 object_not_exist svc -l test=lbsvc-hn
	sleep 10
}

function setup() {
	kubectl delete -f templates/testcases/service/nodeport.yaml || true
	kubectl delete -f templates/testcases/service/clusterip.yaml || true
    kubectl delete -f templates/testcases/service/hostnetwork/nodeport.yaml || true
	kubectl delete -f templates/testcases/service/hostnetwork/clusterip.yaml || true
    kubectl delete -f templates/testcases/service/loadblancer.yaml || true
    kubectl delete -f templates/testcases/service/hostnetwork/loadblancer.yaml || true
	delete_deploy || true
}

# curl $1:$2/healthz in every host ns
function node_request_nodeport() {
    run "kubectl get pod -n kube-system -l app=cello -o name | cut -d '/' -f 2 | xargs -n1 -I {} kubectl exec -i {} -n kube-system -c cello -- curl $1:$2/healthz"
	if [[ "$status" -eq 0 ]]; then
		return 0
	fi
	false
	echo "request $1:$2/healthz in host result: "$result
}

# curl $2:$3/healthz in pods which app=$1
function pod_request_nodeport() {
    run "kubectl get pod -l app=$1 -o name | cut -d '/' -f 2 | xargs -n1 -I {} kubectl exec -i {} -- curl $2:$3/healthz"
	if [[ "$status" -eq 0 ]]; then
		return 0
	fi
	false
	echo "request $2:$3/healthz in $1 result: "$result
}


@test "test nodeport service" {
	retry 5 5 kubectl apply -f templates/testcases/service/nodeport.yaml
	retry 20 5 object_exist pod -l app=nodeport-nginx
    retry 20 5 pod_running pod -l app=nodeport-tool
	sleep 20

    nodeIPs=`kubectl get nodes |grep Ready | awk '{print $1}' |grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | tr "\n" " "|sed -e 's/,$/\n/'`
    for nodeIP in $nodeIPs
    do  
        # node access
        repeat 5 5 node_request_nodeport $nodeIP 30080
        # pod access
        repeat 5 5 pod_request_nodeport nodeport-tool $nodeIP 30080
    done

	[ "$status" -eq "0" ]
	kubectl delete -f templates/testcases/service/nodeport.yaml || true
	delete_deploy
}

@test "test nodeport service with backend use hostnetwork" {
	retry 5 5 kubectl apply -f templates/testcases/service/hostnetwork/nodeport.yaml
	retry 20 5 object_exist pod -l app=nodeport-nginx-hn
    retry 20 5 pod_running pod -l app=nodeport-tool-hn
	sleep 20

    nodeIPs=`kubectl get nodes |grep Ready | awk '{print $1}' |grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | tr "\n" " "|sed -e 's/,$/\n/'`
    for nodeIP in $nodeIPs
    do  
        # node access
        repeat 5 5 node_request_nodeport $nodeIP 30080
        # pod access
        repeat 5 5 pod_request_nodeport nodeport-tool-hn $nodeIP 30080
    done

	[ "$status" -eq "0" ]
	kubectl delete -f templates/testcases/service/hostnetwork/nodeport.yaml || true
	delete_deploy
}

@test "test clusterip service" {
	retry 5 5 kubectl apply -f templates/testcases/service/clusterip.yaml
	retry 20 5 object_exist pod -l app=clusterip-nginx
    retry 20 5 pod_running pod -l app=clusterip-tool
	sleep 20

    clusterip=$(kubectl get svc clusterip-service -o jsonpath='{.spec.clusterIP}')
    port=$(kubectl get svc clusterip-service -o jsonpath='{.spec.ports[0].port}')
    # node access
    repeat 5 5 node_request_nodeport $clusterip $port
    # pod access
    repeat 5 5 pod_request_nodeport clusterip-tool $clusterip $port


	[ "$status" -eq "0" ]
	kubectl delete -f templates/testcases/service/clusterip.yaml || true
	delete_deploy
}


@test "test clusterip service with backend use hostnetwork" {
	retry 5 5 kubectl apply -f templates/testcases/service/hostnetwork/clusterip.yaml
	retry 20 5 object_exist pod -l app=clusterip-nginx-hn
    retry 20 5 pod_running pod -l app=clusterip-tool-hn
	sleep 20

    clusterip=$(kubectl get svc clusterip-service-hn -o jsonpath='{.spec.clusterIP}')
    port=$(kubectl get svc clusterip-service-hn -o jsonpath='{.spec.ports[0].port}')
    # node access
    repeat 5 5 node_request_nodeport $clusterip $port
    # pod access
    repeat 5 5 pod_request_nodeport clusterip-tool-hn $clusterip $port


	[ "$status" -eq "0" ]
	kubectl delete -f templates/testcases/service/hostnetwork/clusterip.yaml || true
	delete_deploy
}


@test "test loadbalancer service" {
    kubectl apply -f templates/testcases/service/loadblancer.yaml
	retry 20 2 object_exist svc -l test=lbsvc
	retry 10 5 svc_ready svc -l test=lbsvc
	ip_addr=$(kubectl get svc loadbalancer-cluster -o jsonpath='{range .status.loadBalancer.ingress[*]}{.ip}{end}')
	retry 5 5 curl $ip_addr
	[ "$status" -eq 0 ]

    kubectl delete -f templates/testcases/service/loadblancer.yaml || true
    delete_deploy
}

@test "test loadbalancer service traffic local" {
    kubectl apply -f templates/testcases/service/loadblancer.yaml
	retry 20 2 object_exist svc -l test=lbsvc
	retry 10 5 svc_ready svc -l test=lbsvc
	ip_addr=$(kubectl get svc loadbalancer-local -o jsonpath='{range .status.loadBalancer.ingress[*]}{.ip}{end}')
	retry 5 5 curl $ip_addr
	[ "$status" -eq 0 ]

    kubectl delete -f templates/testcases/service/loadblancer.yaml || true
    delete_deploy
}

@test "test loadbalancer service with backend use hostnetwork" {
    kubectl apply -f templates/testcases/service/hostnetwork/loadblancer.yaml
	retry 20 2 object_exist svc -l test=lbsvc-hn
	retry 10 5 svc_ready svc -l test=lbsvc-hn
	ip_addr=$(kubectl get svc loadbalancer-cluster-hn -o jsonpath='{range .status.loadBalancer.ingress[*]}{.ip}{end}')
	retry 5 5 curl $ip_addr
	[ "$status" -eq 0 ]

    kubectl delete -f templates/testcases/service/hostnetwork/loadblancer.yaml || true
    delete_deploy
}

@test "test loadbalancer service traffic local with backend use hostnetwork" {
    kubectl apply -f templates/testcases/service/hostnetwork/loadblancer.yaml
	retry 20 2 object_exist svc -l test=lbsvc-hn
	retry 10 5 svc_ready svc -l test=lbsvc-hn
	ip_addr=$(kubectl get svc loadbalancer-local-hn -o jsonpath='{range .status.loadBalancer.ingress[*]}{.ip}{end}')
	retry 5 5 curl $ip_addr
	[ "$status" -eq 0 ]

    kubectl delete -f templates/testcases/service/hostnetwork/loadblancer.yaml || true
    delete_deploy
}