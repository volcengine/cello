# VERSION is the source revision for binary and image building.
VERSION ?= $(shell git log -1 --date='format:%Y%m%d' --format='format:%ad').$(shell git describe --always --contains HEAD)
BRANCH ?= $(shell git rev-parse --abbrev-ref HEAD)

# Information of OS and ARCH
OS = $(shell uname -s)
ARCH = $(shell uname -m)

# Output Directory
OUTPUT ?= output

# Container runtime engine
ENGINE ?= docker

# IMAGE is the Cello contianer image
IMAGE = volcstack/cello
IMAGE_NAME = $(IMAGE):$(IMAGE_TAG)
IMAGE_TAG = $(VERSION)

# GO FLAGS
GOPROXY ?=
GO_FLAGS=-ldflags="-s -w"
CNI_VERSION_LD_FLAG=-ldflags="-X github.com/volcengine/cello/version.Version=$(VERSION)@$(BRANCH)"

tidy: 
	go mod tidy

cello-agent:
	CGO_ENABLED=0 GOOS=linux go build -o $(OUTPUT)/cello-agent $(GO_FLAGS) $(CNI_VERSION_LD_FLAG) \
		./cmd/cello-agent

cello-ctl:
	CGO_ENABLED=0 GOOS=linux go build -o $(OUTPUT)/cello-ctl $(GO_FLAGS) $(CNI_VERSION_LD_FLAG) \
		./cmd/cello-cli

cello-cni:
	CGO_ENABLED=0 GOOS=linux go build -o $(OUTPUT)/cello-cni $(GO_FLAGS) $(CNI_VERSION_LD_FLAG) \
		./cmd/cello-cni

cello-cni-meta:
	CGO_ENABLED=0 GOOS=linux go build -tags meta -o $(OUTPUT)/cello-cni $(GO_FLAGS) $(CNI_VERSION_LD_FLAG) \
		./cmd/cello-cni

cilium-launcher:
	CGO_ENABLED=0 GOOS=linux go build -o $(OUTPUT)/cilium-launcher $(GO_FLAGS) $(CNI_VERSION_LD_FLAG) \
		./cmd/launcher/cilium

protobuf: tidy
	go generate ./pkg/pbrpc

all: pkg image

bin: cello-cni cello-ctl cello-agent cilium-launcher

pkg: bin
	cp ./script/bootstrap/* $(OUTPUT)/
	chmod +x $(OUTPUT)/*.sh

image:
ifdef GOPROXY
	$(ENGINE) build -f ./images/Dockerfile -t $(IMAGE_NAME) --build-arg GOPROXY=$(GOPROXY) .
else
	$(ENGINE) build -f ./images/Dockerfile -t $(IMAGE_NAME) .
endif
	@echo "Built OCI image \"$(IMAGE_NAME)\""

test:
	# Skip race detection for now due to issue: https://github.com/etcd-io/bbolt/issues/391
	go test -v ./... -cover -coverprofile=coverage.out

clean:
	rm -rf ./output

.PHONY: clean protobuf cello-agent cello-cni cello-ctl bin pkg image all test

.DEFAULT: bin
