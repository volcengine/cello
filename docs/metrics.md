# Metrics

Cello exposes metrics through the default port `11414`, path is `:11414/metrics`

## indicators

| No.  | Metrics                  | Labels                      | Description                       |
| ---- | ------------------------ | --------------------------- | --------------------------------- |
| 1    | openapi_latency_ms       | api, error, code, requestId | latency in ms of openapi call     |
| 2    | openapi_error_count      | api, error, code, requestId | count of openapi  error           |
| 3    | metadata_latency_ms      | metadata, error, status     | latency in ms of metadata call    |
| 4    | metadata_error_count     | metadata, error             | count of metadata  error          |
| 5    | rpc_latency_ms           | rpc_api, error              | latency in ms of rpc call         |
| 6    | resource_pool_max_cap    | name, type                  | max capacity of resource pool     |
| 7    | resource_pool_target     | name, type                  | cache target of resource pool     |
| 8    | resource_pool_target_min | name, type                  | cache target min of resource pool |
| 9    | resource_pool_total      | name, type                  | total resource in pool            |
| 10   | resource_pool_available  | name, type                  | available resource in pool        |



## Monitor

Deploy monitor:

* deploy prometheus

  ```
  kubectl apply -f monitor/cello-monitor-prometheus.yaml
  ```

* deploy grafana

  * edit `prometheus_pod_ip` according to prometheus pod

    ```yaml
    apiVersion: v1
    kind: ConfigMap
    data:
      prometheus.yaml: |-
        apiVersion: 1
        datasources:
          - name: Prometheus
            type: prometheus
            # Access mode - proxy (server in the UI) or direct (browser in the UI).
            access: proxy
            editable: true
            url: http://{prometheus_pod_ip}:9090/
            jsonData:
              httpMethod: GET
    
    metadata:
      name: grafana-datasources
      namespace: cello-monitor
    ```

  * apply yaml

  ```bash
  kubectl apply -f monitor/cello-monitor-grafana.yaml
  ```

  **Notic**: This method is only suitable for clusters which size is not too big. The bottleneck of prometheus will be reached if the cluster is too big, and other plan to collecte metrics of Cello are required.

