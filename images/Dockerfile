# cello-base
ARG CILIUM_LLVM_IMAGE=quay.io/cilium/cilium-llvm:0147a23fdada32bd51b4f313c645bcb5fbe188d6@sha256:24fd3ad32471d0e45844c856c38f1b2d4ac8bd0a2d4edf64cffaaa3fd0b21202
ARG CILIUM_BPFTOOL_IMAGE=quay.io/cilium/cilium-bpftool:b5ba881d2a7ec68d88ecd72efd60ac551c720701@sha256:458282e59657b8f779d52ae2be2cdbeecfe68c3d807ff87c97c8d5c6f97820a9
ARG CILIUM_IPROUTE2_IMAGE=quay.io/cilium/cilium-iproute2:4db2c4bdf00ce461406e1c82aada461356fac935@sha256:e4c9ba92996a07964c1b7cd97c4aac950754ec75d7ac8c626a99c79acd0479ab

FROM  ${CILIUM_LLVM_IMAGE} as llvm-dist
FROM  ${CILIUM_BPFTOOL_IMAGE} as bpftool-dist
FROM  ${CILIUM_IPROUTE2_IMAGE} as iproute2-dist

FROM ubuntu:20.04 as cello-base

COPY --from=llvm-dist /usr/local/bin/clang /usr/local/bin/llc /bin/
COPY --from=bpftool-dist /usr/local/bin/bpftool /usr/local/bin/
COPY --from=iproute2-dist /usr/local/bin/ip /usr/local/bin/ss /usr/local/bin/tc /usr/local/bin/

ENV TZ=Asia/Shanghai DEBIAN_FRONTEND=noninteractive
RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections && \
    apt-get update &&\
    apt-get install -y apt-utils kmod libelf1 libmnl0 iptables nftables wget \
            tzdata && \
    ln -fs /usr/share/zoneinfo/${TZ} /etc/localtime && \
    echo ${TZ} > /etc/timezone && \
    dpkg-reconfigure --frontend ${DEBIAN_FRONTEND} tzdata && \
    apt-get purge --auto-remove && apt-get clean && rm -rf /var/lib/apt/lists/*


# cilium
FROM quay.io/cilium/cilium-builder:374a7ec10c5cbc5e9afe4cdd376f95ca592bd9ab@sha256:8d59be6168a25a9855707d63596df9903eef32518710a83879efbf9222f07628 as cilium-builder
ARG GOPROXY
ENV GOPROXY $GOPROXY
WORKDIR /go/src/github.com/cilium
RUN rm -rf cilium
ENV GIT_TAG=v1.10.4
ENV GIT_COMMIT=2a46fd67267716efd58311064e4a91abfa2a0a1c
RUN git clone -b $GIT_TAG --depth 1 https://github.com/cilium/cilium.git && \
    cd cilium && \
    [ "`git rev-parse HEAD`" = "${GIT_COMMIT}" ]
COPY ../patch/cilium /cilium_patch
RUN cd cilium && git apply /cilium_patch/*.patch
RUN cd cilium &&  make PKG_BUILD=1 SKIP_DOCS=true DESTDIR=/tmp/install clean-container build-container install-container


# cni-plugins
FROM docker.io/library/golang:1.20-bullseye as cni-plugins-builder
ARG GOPROXY
ENV GOPROXY $GOPROXY
WORKDIR /go/src/containernetworking
RUN git clone https://github.com/containernetworking/plugins.git --depth=1 --branch v1.2.0
RUN cd plugins && bash build_linux.sh

# cello
FROM docker.io/library/golang:1.20-bullseye as cello-builder
ARG GOPROXY
ENV GOPROXY $GOPROXY
ARG CELLO_META
WORKDIR /go/src/cello/
COPY ../.. .
RUN CELLO_META=$CELLO_META make bin

FROM cello-base
# cello & cilium bin
COPY --from=cello-builder /go/src/cello/output /cello
COPY --from=cni-plugins-builder /go/src/containernetworking/plugins/bin/loopback /containernetworking/plugins/
COPY --from=cilium-builder /tmp/install/. /
RUN mv /opt/cni/bin/cilium-cni /containernetworking/plugins/cilium-cni && \
    ln -s /cello/cello-ctl /bin/cello-ctl && \
    ln -s /cello/cello-agent /bin/cello-agent && \
    ln -s /cello/cilium-launcher /bin/cilium-launcher

# script
RUN mkdir -p /script
COPY ../script/bootstrap/*  /script/
RUN chmod +x /script/*

