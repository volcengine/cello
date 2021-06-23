# Traffic Shaping

## Support
Kernel >= 5.1 needed

| Mode                              | Egress Shaping  | Ingress Shaping |
|-----------------------------------|-----------------|-----------------|
| eni_shared(eni-multi-ip + ipvlan) | ☑️              | -               |
| eni_exclusive                     | ☑️              | -               |
| trunk(branch eni + vlan) (WIP)    | ☑️              | -               |

## Config
to enable traffic shaping, follow config need to add in cello-config configmap

```yaml
kind: ConfigMap
apiVersion: v1
metadata:
  name: cello-config
  namespace: kube-system
data:
  10-cello.conflist: |
    {
      "cniVersion": "0.3.1",
      "name": "cello-chainer",
      "plugins": [
        {
          "type": "cello",
          "capabilities": {
            "bandwidth": true,  #Add
           },
        }
      ]
    }
```
follow config need to add in cilium-config configmap
```yaml
kind: ConfigMap
apiVersion: v1
metadata:
  name: cilium-config
  namespace: kube-system
data:
  enable-bandwidth-manager: "true"
```

## Usage
Add follow annotation to Pod

| Annotation                            | Mean             |
|---------------------------------------| ---------------- |
| `kubernetes.io/egress-bandwidth: 10M` | egress banwidth  |
