# Hubble 集成
## Enable
集成hubble需要在kube-system命名空间下的configmap cilium-config中开启以下参数，可参考 [cilium-agent.md]
```yaml
enable-hubble: "true"
hubble-listen-address: ":4244"
hubble-metrics: "drop,tcp,flow,port-distribution,icmp"  # 开启metrics有性能损失
hubble-metrics-server: ":9091"
```
开启以上参数后，需要重启所有的Cello pod
```bash
kubectl delete pod -l app=cello -n kube-system
```

## 部署 Hubble UI + Hubble Relay

1. 执行以下命令部署，需要本地安装有 `Helm v3`：

   ```bash
   git clone https://github.com/cilium/cilium.git
   cd cilium
   git checkout v1.8.1
   helm install hubble-ui install/kubernetes/cilium/charts/hubble-ui --set global.hubble.ui.enabled=true --set global.hubble.enabled=true --set global.hubble.relay.enabled=true --set ingress.enabled=true --set ingress.hosts={hubble.local} --namespace kube-system
   helm install hubble-relay install/kubernetes/cilium/charts/hubble-relay  --set global.hubble.enabled=true --set global.hubble.relay.enabled=true --set global.hubble.socketPath=/var/run/cilium/hubble.sock --set image.repository=quay.io/cilium/hubble-relay:v1.8.1 --namespace kube-system
   ```

2. 删除 `hubble-relay` deployment yaml文件中的以下亲和性配置：

   ```yaml
   # kubectl -n kube-system edit deployment hubble-relay
   spec:
     template:
       spec:
         # Deletion Begin
         affinity:
           podAffinity:
             requiredDuringSchedulingIgnoredDuringExecution:
               - labelSelector:
                 matchExpressions:
                   - key: k8s-app
                     operator: In
                     values:
                   - cilium
             topologyKey: kubernetes.io/hostname
         # Deletion End
         containers:
         # ...
   ```

3. 访问 Hubble WEB UI  
   将 `hubble-service-address` 指向 service `hubble-ui` 的 IP 地址，访问 `http://hubble-service-address:80`
   也可以自行通过其他方式暴露`hubble-ui`服务

## 采集 metrics

1. 创建以下 SVC，用于被 Prometheus 采集 Metrics：

   ```yaml
   ---
   kind: Service
   apiVersion: v1
   metadata:
     name: hubble-metrics
     namespace: kube-system
     annotations:
       prometheus.io/scrape: 'true'
       prometheus.io/port: '9091'  # 需要和cilium-config中的配置一致
     labels:
       k8s-app: hubble
   spec:
     clusterIP: None
     type: ClusterIP
     ports:
     - name: hubble-metrics
       port: 9091
       protocol: TCP
       targetPort: 9091
     selector:
       app: cello
   ```

2. 采集 Hubble Metrics  
   配置 Prometheus 采集 `kube-system` 下 `hubble-metrics` 即可采集到 Hubble 暴露的指标，可参考 [cilium-metrics] 进行 Dashboard 配置。

[cilium-agent.md]: https://github.com/cilium/cilium/blob/master/Documentation/cmdref/cilium-agent.md
[cilium-metrics]: https://docs.cilium.io/en/v1.8/operations/metrics/