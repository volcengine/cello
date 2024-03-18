# Cello CNI Network Plugin
[English](./README.md) | 简体中文

## 背景
Cello 是一款基于火山引擎VPC网络实现的kubernetes [CNI]插件。通过使用Cello插件可以在云上VPC网络环境下
实现kubernetes集群内部网络的互通，并且在安全组放通的情况下，原生支持kubernetes集群访问同VPC下的其他资源。
Cello使用[辅助ENI]来打通Pod网络，支持共享ENI模式和ENI多IP模式，在两种模式下，支持以下基本通信场景：
* Pod和Pod通信
* Pod和节点通信


Cello 通过集成[Cilium]来替代kube-proxy实现kubernetes Service以获得更好的性能和更丰富的特性，支持以下类型的service：
* ClusterIP
* NodePort
* LoadBalancer

## 工作模式
### 共享ENI模式
![eniip_ipvlan](docs/images/eniip_ipvlan.jpg)
共享ENI模式下，Cello将辅助ENI下的多个辅助私有IP(数量取决于[实例规格])分配给多个Pod，从而获得更高的部署密度。由于每个Pod分配到了一个VPC内的地址，所有Pod和节点在VPC内具有基本相同的“地位”。在VPC网络基础上，支持Pod和所在节点通过本地快路径进行通信。

### 独占ENI模式
![eni](docs/images/eni.jpg)
独占模式下，Cello将辅助ENI直接分配给Pod, 将辅助ENI拉入到Pod的NetNs中并使用辅助ENI的主IP进行通信。从VPC视角，所有Pod和Node具有完全相同的“地位”。受限于ECS可挂载辅助ENI的数量，这种模式下Pod部署密度较低。在VPC网络基础上，支持Pod和所在节点通过本地`veth-pair`进行通信。

## ENI 创建
<img alt="feishu" height="400" src="./docs/images/eni_allocation.jpg"/>

Cello 以 daemonset 的形式部署在每个节点上，每个 Cello 实例都会独立申请辅助 ENI。申请 ENI 时会从用户配置的subnets中选择一个，并使用用户配置的全部安全组。 `eni_exclusive` 模式直接使用eni，节点上可调度的pod数量等于`eni_quota-1`。在`eni_shared`模式下，节点上可调度的pod数量等于`(eni_quota-1)*ip_quota_per_eni`。 Cello 创建的 ENI 会携带一些标签来标识创建者，如果 Cello 存活，Cello 会根据标签定期检查和回收自己泄露的 ENI。在集群中部署 opeartor 来回收删除节点时 detached 的 ENI 可以进一步避免ENI的泄漏。删除集群后，用户仍需要检查是否有 ENI 泄漏。

## 调度感知
无论是哪种模式，Cello 都会通过 [device plugin] 报告可用网络资源的数量，以便调度器将 pod 调度到有资源的节点上。用户可以通过向 pod 的第一个容器添加以下 [requests and limits] 字段来使用此机制。

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

## 构建
#### 依赖
- `protobuf [required]`
- `go 1.20+ [required]`
- `docker [option] `

#### 编译bin
```bash
# make完后所有部署需要的程序和配置文件位于./output 目录
git clone [todo]
cd cello
go mod download
make bin
```

#### 编译镜像
```bash
git clone [todo]
cd cello
go mod download
make image # 默认使用docker，可通过ARG `ENGINE` 指定使用podman进行编译
```

## 部署
### 安装 Kubernetes
* 准备火山引擎 ECS实例 （需要 ECS 实例内核版本 4.19+，经过测试的OS为veLinux 1.0 with 5.10 kernel）
* 安装Kubernetes，推荐使用 [kubeadm]

### 安装Cello
* 确保传递给Cello的`credentialAccessKeyId` 或 `ramRole`附加了所需的 [IAM策略](docs/iam-policy.md)
* 参考 [config.md](docs/config.md) 准备配置
* 使用helm安装（需要helm 3.0）
    ```shell
    helm install cello chart
    ```

## 测试
### 单元测试
```bash
git clone [todo]
cd cello
go mod download
make test
```
### 功能测试
确保集群正确安装了Cello, 并且 `kubectl` 可连接到集群
```bash
git clone [todo]
cd cello
./tests/test.sh
```

## 社区
### 贡献
详情见 [CONTRIBUTING.md](./CONTRIBUTING.md)。

### 联系方式
欢迎通过 Github `issues` 和 `pull requests` 进行交流， 也可以通过邮件与我们进行交流,欢迎点击[链接](https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=f55qe2de-ddae-4d89-a262-9eee33c5f5d2)或扫描下方飞书二维码加入Cello开源交流群进行咨询。  

<img alt="feishu" height="300" src="./docs/images/feishu.png"/>


### 加入我们
为cello项目反馈贡献的最好方式就是加入我们, 如果您对云网络或云原生开发感兴趣欢迎点击[链接](https://job.toutiao.com/s/iePyAdS4)获取更多详情。

### 许可证
Cello 使用 Apache 2.0 证书, 详情见 [LICENSE](./LICENSE)。


[CNI]: https://www.cni.dev/
[辅助ENI]: https://www.volcengine.com/docs/6401/68940#%E7%BD%91%E5%8D%A1
[Cilium]: https://cilium.io/
[实例规格]: https://www.volcengine.com/docs/6396/70840
[kubeadm]: https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/

