# Cello 参数配置

Cello当前支持通过 Configmap 来配置 Cello-agent 和 Cilium-agent 的运行参数；
支持部分参数的动态感知和运行时修改；支持集群级别的全局配置和节点级别的独立配置；

## Cluster Scope Config
### Cello-agent config

```yaml
kind: ConfigMap
apiVersion: v1
metadata:
  name: cello-config
  namespace: kube-system
data:
  conf: |
    {
      "subnets":[
              "subnet-xxx",
              "subnet-yyy"
      ],
      "securityGroups": [
              "sg1",
              "sg2"
      ],
      "ramRole": "KubernetesNodeRoleForECS",
      "openApiAddress": "open-boe.volcengineapi.com",
      "poolTarget": 3,
      "poolTargetMin": 5,
      "poolMaxCapProbe": true,
      "poolMonitorIntervalSec": 120,
      "networkMode": "eni_shared",
      "ipFamily": "ipv4"
    }
```
必选参数：
* `subnets`: Pod所使用的子网
* `securityGroups`: Pod所使用的安全组
* `openApiAddress`: 访问OpenAPI的服务地址，由火山引擎提供
* `ramRole`: 用于访问OpenAPI时鉴权，与`credentialAccessKeyId`、`credentialAccessKeySecret`择一即可
* `credentialAccessKeyId`: 用于访问OpenAPI时鉴权
* `credentialAccessKeySecret`: 用于访问OpenAPI时鉴权  

可选参数：
* `credentialServerAddress`: 通过 `ramRole` 获取授权时所用的sts服务地址
* `poolTarget`: 池化资源缓存数量目标值
* `poolTargetMin`: 池化资源缓存数量最小值（空闲资源数量和已用资源数量的总和）
<!--
* `networkMode`: 网络模式，支持`eni_shared`、`eni_exclusive`, 默认为 `eni_shared`
* `ipFamily`: 协议族，支持 `ipv4`、`ipv6`、`dual`, 默认为 `ipv4`
-->

#### Dynamic Config <span id="dynamic-config"></span>  
Cello 支持在运行时更改部分参数而无需重启 Cello Pod，其方式是直接修改cello-config，目前支持以下参数的运行时变配，
其他参数暂不支持(需要重启 Cello Pod后生效):
* subnets  #常见的场景是扩展新的subnet，如果删除subnet，除非使用该subnet的所有ENI被删除，否则该subnet仍会被继续使用
* securityGroups  #谨慎修改，若集群内pod所属的安全组不一致，可能会造成连通性问题
* poolTarget
* poolTargetMin


### Cilium-agent config
功能上支持通过以下方式配置 [cilium-agent.md]中的所有参数
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cilium-config
  namespace: kube-system
data:
  debug: "false"
```
为了Cello的正常运行，除非用户明确知道更改配置所带来的影响，否则不建议用户更改以下参数：

```yaml
agent-health-port
bpf-map-dynamic-size-ratio
disable-envoy-version-check
direct-routing-device
datapath-mode
enable-endpoint-health-checking
enable-host-legacy-routing
enable-local-node-route
ipam
ipvlan-master-device
kube-proxy-replacement
node-port-mode
tunnel
enable-ipv4
enable-ipv4-masquerade
ipv4-range
enable-ipv6
enable-ipv6-masquerade
ipv6-range
```

## Node Scope Config
除以上全集群范围的配置方式，Cello支持为指定的节点或节点池独立配置部分参数，如下：
* poolTargetLimit
* poolTarget
* poolTargetMin
* enableTrunk
* securityGroups
* subnets

### 配置方式
通过node label为一个或一组 node 指定存储有以上参数的configmap，key为`vke.volcengine.com/vpc-cni-config`，
value为 `{nameSpace}.{configmap-name}`，例如：
```yaml
apiVersion: v1
kind: Node
metadata:
  annotations:
    kubeadm.alpha.kubernetes.io/cri-socket: unix:///var/run/containerd/containerd.sock
  creationTimestamp: "2022-05-14T07:04:51Z"
  labels:
    beta.kubernetes.io/arch: amd64
    beta.kubernetes.io/instance-type: ecs.g1.xlarge
    beta.kubernetes.io/os: linux
    vke.volcengine.com/vpc-cni-config: kube-system.PoolConfigForNodexxx

---
kind: ConfigMap
apiVersion: v1
metadata:
  name: PoolConfigForNodexxx
  namespace: kube-system
data:
  conf: |
    {
      "subnets":[
              "subnet-zzz",
              "subnet-kkk"
      ],
      "securityGroups": [
              "sg3",
              "sg4"
      ],
      "poolTargetLimit"： 0.7,
      "poolTarget": 1,
      "poolTargetMin": 3,
      "enableTrunk": false,
    }

```
Cello-agent 启动后会先根据cluster scope的configmap生成配置，之后若通过以上方式为节点指定了配置，
则节点级的参数会覆盖集群级的参数以生成最终的配置。需要注意的是，为节点指定了配置后，[运行时更改参数]将不再被支持。


[cilium-agent.md]: https://github.com/cilium/cilium/blob/master/Documentation/cmdref/cilium-agent.md
[运行时更改参数]: #dynamic-config