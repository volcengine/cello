#!/usr/bin/env bash

# 确保脚本是可重入的

init_node_bpf() {
  nsenter -t 1 -m -- bash -c '
  mount | grep "/sys/fs/bpf type bpf" || {
  # Mount the filesystem until next reboot
  echo "Mounting BPF filesystem..."
  mount bpffs /sys/fs/bpf -t bpf

  echo "Link information:"
  ip link

  echo "Routing table:"
  ip route

  echo "Addressing:"
  ip -4 a
  ip -6 a
#  date > /tmp/cilium-bootstrap-time
  echo "Node initialization complete"
}'
}

set -o errexit
set -o nounset

# check kernel version & enable cilium
read KERNEL_MAJOR_VERSION KERNEL_MINOR_VERSION < <(uname -r | awk -F . '{print $1,$2}')
# kernel version equal and above 4.19
if { [ "$KERNEL_MAJOR_VERSION" -eq 4 ] && [ "$KERNEL_MINOR_VERSION" -ge 19 ]; } ||
    [ "$KERNEL_MAJOR_VERSION" -gt 4 ]; then
    echo "Init node BPF"
    init_node_bpf
else
  echo "Linux kernel version <= 4.19, skipping cilium config"
  exit 1
fi

#echo "install cni"
#mkdir -p /opt/cni/bin/ /etc/cni/net.d/

#install /usr/bin/cilium-cni /opt/cni/bin/
#chmod +x /opt/cni/bin/cilium-cni

echo "disable rp_filter"
sysctl -w net.ipv4.conf.eth0.rp_filter=0

#限速
#echo "modprobe sch_htb"
#modprobe sch_htb || echo "modprobe sch_htb failed"
echo "modprobe ipvlan"
modprobe ipvlan || echo "modprobe ipvlan failed"

echo "[`date`] init.sh execute finish" > /tmp/init

export DATASTORE_TYPE=kubernetes
if [ "$DATASTORE_TYPE" = "kubernetes" ]; then
    if [ -z "$KUBERNETES_SERVICE_HOST" ]; then
        echo "cilium need k8s datastore, but can not found [KUBERNETES_SERVICE_HOST] env, exiting"
        exit 1
    fi
fi

# 注册crd，更新ciliumnode ipam
mkdir -p /cilium && cd /cilium

## run cello-cilium-hook
#/usr/bin/cello-cilium-hook 2>&1 1>ciliumnode.log &

echo "run cilium-agent use config-dir: /etc/cilium/cilium-config"
exec cilium-agent --config-dir=/etc/cilium/cilium-config