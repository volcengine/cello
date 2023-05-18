
# Create kubernetes cluster

Edit cluster variables in file `ci/tf/example.tfvars` and run:

``` bash
./provision.sh
```
kubectl config file locates at `ci/kube/config-public`.

```bash
export KUBECONFIG=ci/kube/config-public
kubectl get nodes -A -o wide
```

# Destroy kubernetes cluster

Uninstall Cello and then run:

``` bash
./destroy.sh
```

# Run conformance tests

``` bash
./conformance_test.sh
```
