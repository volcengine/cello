# Cello CNI Network Plugin

English | [简体中文](./README-zh_CN.md)

## Overview
Cello is a kubernetes [CNI] plugin based on the Volcengine VPC network. By using the Cello plugin, the intercommunication of the internal network of the kubernetes cluster can be realized in the VPC network environment on the cloud. The kubernetes cluster can natively access to other resources under the same VPC when the access is allowed by security group. Cello uses [secondary ENI] to build the Pod network, and supports shared ENI mode and ENI multi-IP mode. In both modes, the following basic communication scenarios are supported:
* Pod to Pod communication
* Pod to Node communication

Cello replaces kube-proxy with [Cilium] to implement kubernetes services to achieve better performance and richer features. It supports the following types of services:
* ClusterIP
* NodePort
* LoadBalancer

## Cello mode

### ENI-Multi-IP
![eniip_ipvlan](docs/images/eniip_ipvlan.jpg)
In the ENI-Multi-IP mode, Cello assigns multiple secondary private IPs under the secondary ENI to multiple Pods to achieve higher deployment density. The number of Pods on ECS depends on instance type ([limit]). Since each Pod is assigned an address within the VPC, all Pods and Nodes are almost the same in the VPC perspective. In addition to communicating through VPC, Pod can communicate with its Node through local fast path.

### Exclusive-ENI
![eni](docs/images/eni.jpg)
In exclusive mode, Cello assigns the secondary ENI directly to the Pod, pulls the secondary ENI into the Pod's NetNs and uses the primary IP of the secondary ENI for communication. From the perspective of VPC, all Pods and Nodes are the same. Limited by the number of secondary ENIs that can be attached on the ECS, the Pod deployment density in this mode is much lower. In addition to communicating through VPC, Pod also can communicate with its Node through the local `veth-pair`.



## ENI Allocation

<img alt="feishu" height="400" src="./docs/images/eni_allocation.jpg"/>

Cello is deployed on each node in the form of daemonset, and each Cello instance will independently apply for secondary ENIs and use them to configure pod network. Each ENI will select one of the subnets configured by the user and all security groups configured by the user.   
* In `eni_exclusive` mode, eni is used directly, the number of pods that can be scheduled on the node is equal to `eni_quota-1`. 
* In `eni_shared` mode,  the number of pods that can be scheduled on the node is equal to `(eni_quota-1)*ip_quota_per_eni`.

ENI created by Cello will carry some tags to indicate the creator, and Cello will periodically check and recycle its own leaked ENI according to the tags if it is alive. Deploying an operator in the cluster to reclaim the detached ENI when deleting nodes can further avoid ENI leaks, and user intervention is required while cluster is deleted.



## Scheduling Perception

Regardless of the mode, Cello will report the number of available network resources by [device plugin] so that the scheduler can schedule pods to nodes with resources. Users can use this mechanism by adding following [requests and limits] fields to the first container of pod.

```yaml
# eni_shared mode:
resources:
  limits:
    vke.volcengine.com/eni-ip: "1"
  requests:
    vke.volcengine.com/eni-ip: "1"
# eni_exclusive mode:
resources:
  limits:
    vke.volcengine.com/eni: "1"
  requests:
    vke.volcengine.com/eni: "1"
```

## Build

### Required
* protobuf 
* go 1.20+ 
* docker [option]

### Bin
```bash
git clone [todo]
cd cello
go mod download
make bin
```
After make, all the programs and configuration files required for deployment are located in the `output` directory.

### Image
```bash
git clone [todo]
cd cello
go mod download
make image 
```
Docker is used by default, and can be compiled with podman through ARG `ENGINE`. 

You also can specify image name by ARG `IMAGE_NAME` and specify image tag by ARG `IMAGE_TAG`.

```bash
IMAGE_NAME=k8s.com/cello IMAGE_TAG=v1.0.0 make image
```

## Installation
### Install Kubernetes
* Prepare the Volcengine ECS instance (ECS instance kernel version 4.19+ is required, and the tested OS is veLinux 1.0 with 5.10 kernel).
* Install Kubernetes, [kubeadm] is recommended.

### Install Cello
* Make sure the `credentialAccessKeyId` or `ramRole` passed to Cello has associated the required [IAM policy](docs/iam-policy.md).
* Refer to [config.md](docs/config.md) to prepare the configuration.
*  Install using helm (helm 3.0 is required).
    ```shell
    helm install cello chart
    ```

## Test
### Unit Test
```bash
git clone [todo]
cd cello
go mod download
make test
```
### Function Test  
Make sure the cluster has installed Cello correctly and `kubectl` can connect to the cluster.
```bash
git clone [todo]
cd cello
./tests/test.sh
```

## Built With
[Cilium]: Cello integrate Cilium components to support NetworkPolicy and optimize the Service performance. Cilium watch NetworkPolicy and Service configuration and inject ebpf program into pod's primary device.

## Community
### Contributing
See the [CONTRIBUTING.md](./CONTRIBUTING.md) file for details.

### Contact
If you have any questions or want to contribute, you are welcome to communicate with us via GitHub issues or emails. 
Join the Cello [Lark group](https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=f55qe2de-ddae-4d89-a262-9eee33c5f5d2) to chat with other cello developers or ask any questions. You can also use lark scan QR code below.

<img alt="feishu" height="300" src="./docs/images/feishu.png"/>

### Join Us
The best way to contribute to the Cello project is to join us. If you are interested in Cloud Networking or Cloud Native development, please click this [link](https://job.toutiao.com/s/iePyAdS4) for details.


### License
Cello is under the Apache 2.0 license. See the [LICENSE](./LICENSE) file for details.


[CNI]: https://www.cni.dev/
[secondary ENI]: https://www.volcengine.com/docs/6401/68940#%E7%BD%91%E5%8D%A1
[device plugin]: https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/device-plugins/
[requests and limits]: https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
[Cilium]: https://cilium.io/
[limit]: https://www.volcengine.com/docs/6396/70840
[kubeadm]: https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/