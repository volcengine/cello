# 主机网络栈路由

## 背景
在一些特殊的通信场景下，需要将目的地址是特定cidr的流量转发给主机网络栈进行处理。常见的如DNS缓存方案
node-local-dns 中，Local DNS 缓存作为 DaemonSet 部署在每个集群节点上，通过 Link-Local Address 暴露缓存服务。
如需使用本地DNS缓存，可以将 Link-Local Address 设置到主机网络栈路由中。这样节点上的所有Pod就可以通过Link-Local Address访问到本地DNS缓存。

## 配置流程
1. 在kube-system命名空间下，修改configmap `cello-config`，修改`redirectToHostCIDRs`字段，添加需要转发到主机网络栈的cidr
    ```yaml
      10-cello.conflist: |
        {
          "cniVersion": "0.3.1",
          "name": "cello-chainer",
          "plugins": [
            {
              "type": "cello",
              ...
              "redirectToHostCIDRs": ["169.254.0.0/16"]
            }
          ]
        }
    ```

2. 重启所有Cello Pod  
    ```bash
    kubectl delete pod -l app=cello -n kube-system
    ```

3. Cello pod重启后登录任意节点执行以下命令确认配置是否生效
    ```bash
    cat /etc/cni/net.d/10-cello.conflist
    ```
4. 重建Pod后，Pod即可访问该新网段。