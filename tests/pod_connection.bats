#!/usr/bin/env bats

load utils/utils

function delete_deploy() {
	retry 20 2 object_not_exist pod -l app=samenode-nginx
	retry 20 2 object_not_exist pod -l app=crossnode-nginx
	sleep 10
}

function setup() {
	kubectl delete -f templates/testcases/pod_connection/samenode.yaml || true
	kubectl delete -f templates/testcases/pod_connection/crossnode.yaml || true
	delete_deploy || true
}

function node_request_pod() {
	run "kubectl get pod -n kube-system -l app=cello -o name | cut -d '/' -f 2 | xargs -n1 -I {} kubectl exec -i {} -n kube-system -c cello -- curl $1:80/healthz"
	if [[ "$status" -eq 0 ]]; then
		return 0
	fi
	false
	echo "request $1:80/healthz result: "$result
}

# pods which app=$1 request ip list $2
function pod_request_pod() {
    run "kubectl get pod -l app=$1 -o name | cut -d '/' -f 2 | xargs -n1 -I {} kubectl exec -i {} -- curl $2:80/healthz"
	if [[ "$status" -eq 0 ]]; then
		return 0
	fi
	false
	echo "request $1:80/healthz result: "$result
}

@test "pod connection same node" {
	retry 5 5 kubectl apply -f templates/testcases/pod_connection/samenode.yaml
	retry 20 5 object_exist pod -l app=samenode-nginx
	sleep 20

	podIPs=`kubectl get pod -l app=samenode-nginx -o wide | awk 'NR!=1 {print $6}' | tr "\n" " "|sed -e 's/,$/\n/'`
	for podIP in $podIPs
	do
		retry 5 5 node_request_pod $podIP
		retry 5 5 pod_request_pod samenode-nginx $podIP
	done
	[ "$status" -eq "0" ]
	kubectl delete -f templates/testcases/pod_connection/samenode.yaml || true
	delete_deploy
}


@test "pod connection cross node" {
	retry 5 5 kubectl apply -f templates/testcases/pod_connection/crossnode.yaml
	retry 20 5 object_exist pod -l app=crossnode-nginx
	sleep 20

	podIPs=`kubectl get pod -l app=crossnode-nginx -o wide | awk 'NR!=1 {print $6}' | tr "\n" " "|sed -e 's/,$/\n/'`
	for podIP in $podIPs
	do
		retry 5 5 node_request_pod $podIP
		retry 5 5 pod_request_pod crossnode-nginx $podIP
	done
	[ "$status" -eq "0" ]
	kubectl delete -f templates/testcases/pod_connection/crossnode.yaml || true
	delete_deploy
}
