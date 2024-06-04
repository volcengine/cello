ARG UBUNTU_IMAGE=docker.io/library/ubuntu:20.04
ARG CILIUM_LLVM_IMAGE=quay.io/cilium/cilium-llvm:0147a23fdada32bd51b4f313c645bcb5fbe188d6
ARG CILIUM_BPFTOOL_IMAGE=quay.io/cilium/cilium-bpftool:b5ba881d2a7ec68d88ecd72efd60ac551c720701
ARG CILIUM_IPROUTE2_IMAGE=quay.io/cilium/cilium-iproute2:4db2c4bdf00ce461406e1c82aada461356fac935
ARG CILIUM_IPTABLES_IMAGE=quay.io/cilium/iptables-20.04:e6f83206c57e606282056903ffd3aab0183bdaed

# runtime
FROM ${CILIUM_LLVM_IMAGE} as llvm-dist
FROM ${CILIUM_BPFTOOL_IMAGE} as bpftool-dist
FROM ${CILIUM_IPROUTE2_IMAGE} as iproute2-dist
FROM ${CILIUM_IPTABLES_IMAGE} as iptables-dist

FROM --platform=${TARGETPLATFORM} ${UBUNTU_IMAGE} as rootfs
ENV FORCE_BUILD=3

# Update ubuntu packages to the most recent versions
ARG TZ=Asia/Shanghai
ENV TZ=${TZ} DEBIAN_FRONTEND=noninteractive
RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections && \
    apt-get update && \
    apt-get install -y jq apt-utils kmod libelf1 libmnl0 iptables nftables curl bash-completion tzdata && \
    ln -fs /usr/share/zoneinfo/${TZ} /etc/localtime && \
        echo ${TZ} > /etc/timezone && \
        dpkg-reconfigure --frontend ${DEBIAN_FRONTEND} tzdata && \
        apt-get purge --auto-remove && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=iptables-dist /iptables /iptables
RUN dpkg -i /iptables/*\.deb && rm -rf /iptables

COPY iptables-wrapper-installer.sh /iptables-wrapper-installer.sh
RUN /iptables-wrapper-installer.sh

COPY --from=llvm-dist /usr/local/bin/clang /usr/local/bin/llc /bin/
COPY --from=bpftool-dist /usr/local /usr/local
COPY --from=iproute2-dist /usr/local /usr/local

FROM scratch
COPY --from=rootfs / /