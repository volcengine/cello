ARG GOLANG_IMAGE=docker.io/library/golang:1.20-bullseye
ARG UBUNTU_IMAGE=docker.io/library/ubuntu:20.04
ARG CILIUM_LLVM_IMAGE=quay.io/cilium/cilium-llvm:0147a23fdada32bd51b4f313c645bcb5fbe188d6
ARG CILIUM_BPFTOOL_IMAGE=quay.io/cilium/cilium-bpftool:b5ba881d2a7ec68d88ecd72efd60ac551c720701
ARG CILIUM_IPROUTE2_IMAGE=quay.io/cilium/cilium-iproute2:4db2c4bdf00ce461406e1c82aada461356fac935
ARG CILIUM_IPTABLES_IMAGE=quay.io/cilium/iptables-20.04:e6f83206c57e606282056903ffd3aab0183bdaed
ARG CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:374a7ec10c5cbc5e9afe4cdd376f95ca592bd9ab

# runtime
FROM ${CILIUM_LLVM_IMAGE} as llvm-dist
FROM ${CILIUM_BPFTOOL_IMAGE} as bpftool-dist
FROM ${CILIUM_IPROUTE2_IMAGE} as iproute2-dist
FROM ${CILIUM_IPTABLES_IMAGE} as iptables-dist

FROM --platform=${TARGETPLATFORM} ${UBUNTU_IMAGE} as rootfs
ENV FORCE_BUILD=3

ARG HTTP_PROXY
ARG HTTPS_PROXY
ENV HTTP_PROXY $HTTP_PROXY
ENV HTTPS_PROXY $HTTPS_PROXY

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

COPY images/runtime/iptables-wrapper-installer.sh /iptables-wrapper-installer.sh
RUN /iptables-wrapper-installer.sh

COPY --from=llvm-dist /usr/local/bin/clang /usr/local/bin/llc /bin/
COPY --from=bpftool-dist /usr/local /usr/local
COPY --from=iproute2-dist /usr/local /usr/local

FROM scratch as runtime
COPY --from=rootfs / /


# cilium
FROM --platform=${TARGETPLATFORM} ${CILIUM_BUILDER_IMAGE} as cilium-builder
ARG GOPROXY
ENV GOPROXY $GOPROXY
WORKDIR /go/src/github.com/cilium
RUN rm -rf cilium
ENV GIT_TAG=v1.10.4
ENV GIT_COMMIT=2a46fd67267716efd58311064e4a91abfa2a0a1c
RUN git clone -b $GIT_TAG --depth 1 https://github.com/cilium/cilium.git && \
    cd cilium && \
    [ "`git rev-parse HEAD`" = "${GIT_COMMIT}" ]
COPY patch/cilium /cilium_patch
RUN cd cilium && git apply /cilium_patch/*.patch
RUN cd cilium &&  make PKG_BUILD=1 SKIP_DOCS=true DESTDIR=/tmp/install clean-container build-container install-container

# Hubble CLI
FROM --platform=${TARGETPLATFORM} ${CILIUM_BUILDER_IMAGE} as hubble
ARG TARGETOS=linux
ARG TARGETARCH=amd64
COPY images/hubble-version.sh /tmp/hubble-version.sh
COPY images/download-hubble.sh /tmp/download-hubble.sh
RUN /tmp/download-hubble.sh
RUN /out/${TARGETOS}/${TARGETARCH}/bin/hubble completion bash > /out/linux/bash_completion

# cni-plugins
FROM --platform=${TARGETPLATFORM} ${GOLANG_IMAGE} as cni-plugins-builder
ARG GOPROXY
ENV GOPROXY $GOPROXY
WORKDIR /go/src/containernetworking
RUN git clone https://github.com/containernetworking/plugins.git --depth=1 --branch v1.2.0
RUN cd plugins && CGO_ENABLED=0 ./build_linux.sh

# cello
FROM --platform=${TARGETPLATFORM} ${GOLANG_IMAGE} as cello-builder
ARG GOPROXY
ENV GOPROXY $GOPROXY
WORKDIR /go/src/cello/
COPY . .
RUN make bin

FROM --platform=${TARGETPLATFORM} runtime
RUN groupadd -f cilium && echo ". /etc/profile.d/bash_completion.sh" >> /etc/bash.bashrc
ARG TARGETOS=linux
ARG TARGETARCH=amd64

ENV HUBBLE_SERVER=unix:///var/run/cilium/hubble.sock
COPY --from=hubble /out/${TARGETOS}/${TARGETARCH}/bin/hubble /bin/hubble
COPY --from=hubble /out/${TARGETOS}/bash_completion /etc/bash_completion.d/hubble

# cello & cilium bin
COPY --from=cni-plugins-builder /go/src/containernetworking/plugins/bin/loopback /containernetworking/plugins/
COPY --from=cilium-builder /tmp/install/. /
COPY --from=cello-builder /go/src/cello/output /cello
RUN mv /opt/cni/bin/cilium-cni /containernetworking/plugins/cilium-cni && \
    ln -s /cello/bin/cello-ctl /bin/cello-ctl && \
    ln -s /cello/bin/cello-agent /bin/cello-agent && \
    ln -s /cello/bin/cilium-launcher /bin/cilium-launcher

# script
RUN mkdir -p /script
COPY script/bootstrap/*  /script/
RUN chmod +x /script/*
