# VERSION is the source revision for binary and image building.
VERSION ?= $(shell git log -1 --date='format:%Y%m%d' --format='format:%ad').$(shell git describe --always --contains HEAD)
BRANCH ?= $(shell git rev-parse --abbrev-ref HEAD)
DATE = $(shell date +"%Y-%m-%d_%H:%M:%S")
COMMIT = $(shell git rev-parse HEAD | head -c 8)

# Information of OS and ARCH
OS = $(shell uname -s)
ARCH = $(shell uname -m)

# Output Directory
OUTPUT ?= output

# Container runtime engine
ENGINE ?= docker

# IMAGE Name and Tag
IMAGE_NAME ?= volcstack/cello
IMAGE_TAG ?= $(VERSION)
IMAGE_NAME_TAG ?= $(IMAGE_NAME):$(IMAGE_TAG)

# GO FLAGS
GOPROXY ?=
GO_FLAGS=-ldflags="-s -w"
CNI_VERSION_LD_FLAG=-ldflags="-X github.com/volcengine/cello/pkg/version.Version=$(VERSION)@$(BRANCH) -X github.com/volcengine/cello/pkg/version.GitCommit=$(COMMIT)"
BUILD_INFO=-ldflags="-X main.BuildInfo=$(VERSION)@$(BRANCH)_$(DATE)"

# BUILD FLAGS
CELLO_META ?=

BUILD_ARGS = --build-arg HTTPS_PROXY=$(HTTPS_PROXY) --build-arg GOPROXY=$(GOPROXY)
ifdef GOPROXY
	BUILD_ARGS+=--build-arg GOPROXY=$(GOPROXY)
endif
ifdef CELLO_META
	BUILD_ARGS+=--build-arg CELLO_META=$(CELLO_META)
endif

tidy:
	go mod tidy

cello-agent:
	CGO_ENABLED=0 GOOS=linux go build -o $(OUTPUT)/cello-agent $(GO_FLAGS) $(CNI_VERSION_LD_FLAG) \
		./cmd/cello-agent

cello-ctl:
	CGO_ENABLED=0 GOOS=linux go build -o $(OUTPUT)/cello-ctl $(GO_FLAGS) $(CNI_VERSION_LD_FLAG) $(BUILD_INFO)\
		./cmd/cello-cli

cello-cni:
ifdef CELLO_META
	CGO_ENABLED=0 GOOS=linux go build -tags meta -o $(OUTPUT)/cello-cni $(GO_FLAGS) $(CNI_VERSION_LD_FLAG) \
		./cmd/cello-cni
	$(info with meta)
else
	CGO_ENABLED=0 GOOS=linux go build -o $(OUTPUT)/cello-cni $(GO_FLAGS) $(CNI_VERSION_LD_FLAG) \
    	./cmd/cello-cni
endif

cilium-launcher:
	CGO_ENABLED=0 GOOS=linux go build -o $(OUTPUT)/cilium-launcher $(GO_FLAGS) $(CNI_VERSION_LD_FLAG) \
		./cmd/launcher/cilium

protobuf: tidy
	go generate ./pkg/pbrpc

all: pkg image

bin: tidy cello-cni cello-ctl cello-agent cilium-launcher

pkg: bin
	cp ./script/bootstrap/* $(OUTPUT)/
	chmod +x $(OUTPUT)/*.sh

image:
	$(ENGINE) build -f ./images/Dockerfile -t $(IMAGE_NAME_TAG) ${BUILD_ARGS} .
	@echo "Built OCI image \"$(IMAGE_NAME)\""

test:
	# Skip race detection for now due to issue: https://github.com/etcd-io/bbolt/issues/391
	go test -v ./... -cover -coverprofile=coverage.out

clean:
	rm -rf ./output

.PHONY: clean protobuf cello-agent cello-cni cello-ctl bin pkg image all test

.DEFAULT: bin
