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
read KERNEL_MAJOR_VERSION KERNEL_MINOR_VERSION < <(uname -r | awk -F . '{print $1,$2}')
# kernel version equal and above 4.19
if { [ "$KERNEL_MAJOR_VERSION" -eq 4 ] && [ "$KERNEL_MINOR_VERSION" -ge 19 ]; } ||
    [ "$KERNEL_MAJOR_VERSION" -gt 4 ]; then
    echo "Init node BPF"
    init_node_bpf
else
  echo "Linux kernel version <= 4.19, cant install cilium"
  exit 1
fi

echo "modprobe ipvlan"
modprobe ipvlan || echo "modprobe ipvlan failed"
echo "modprobe sch_htb"
modprobe sch_htb || echo "modprobe sch_htb failed"

# install CNIs
/bin/cp -f /etc/cello/net.d/* /etc/cni/net.d
/bin/cp -f /cello/cello-cni /opt/cni/bin
/bin/cp -f /containernetworking/plugins/* /opt/cni/bin/
