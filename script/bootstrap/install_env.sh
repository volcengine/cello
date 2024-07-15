#!/usr/bin/env bash

set -e
set -x
set -o nounset

CURDIR=$(
  cd $(dirname $0) || exit
  pwd
)

cd "${CURDIR}" || exit

init_node_bpf() {
  nsenter -t 1 -m -- bash -c '
  mount | grep "/sys/fs/bpf type bpf" || {
  # Mount the filesystem until next reboot
  echo "Mounting BPF filesystem..."
  mount bpffs /sys/fs/bpf -t bpf

  echo "Link information:"
  ip link

  echo "Routing table:"
  ip -4 route
  ip -6 route

  echo "Addressing:"
  ip -4 addr
  ip -6 addr
#  date > /tmp/cilium-bootstrap-time
  echo "Node initialization complete"
}'
}

# check kernel version & enable cilium
# kernel version equal and above 5.0
read KERNEL_MAJOR_VERSION KERNEL_MINOR_VERSION < <(uname -r | awk -F . '{print $1,$2}')
if [ "$KERNEL_MAJOR_VERSION" -gt 4 ]; then
    echo "Linux kernel >= 5.0, initializing node BPF"
    init_node_bpf
# kernel version equal and above 4.19
elif [ "$KERNEL_MAJOR_VERSION" -eq 4 ] && [ "$KERNEL_MINOR_VERSION" -ge 19 ]; then
    echo "Linux kernel >= 4.19, initializing node BPF"
    init_node_bpf
# kernel version equal and above 4.18 for RHEL release
elif  [ -f "/etc/redhat-release" ] && [ "$KERNEL_MAJOR_VERSION" -eq 4 ] && [ "$KERNEL_MINOR_VERSION" -ge 18 ];  then
    echo "Linux kernel >= 4.18-RHEL, initializing node BPF"
    init_node_bpf
else
  echo "Linux kernel version < 4.19 ( or 4.18 for RHEL kernel), cant install cilium"
  exit 1
fi

echo "modprobe ipvlan"
modprobe ipvlan || echo "modprobe ipvlan failed"
echo "modprobe sch_htb"
modprobe sch_htb || echo "modprobe sch_htb failed"

# install CNIs
/bin/cp -f /etc/cello/net.d/* /etc/cni/net.d
/bin/cp -f /cello/cni/* /opt/cni/bin/
/bin/cp -f /containernetworking/plugins/* /opt/cni/bin/
