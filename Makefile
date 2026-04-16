SHELL := /bin/zsh

PROJECT_DIR := $(shell pwd)
DIST_DIR := $(PROJECT_DIR)/dist
BIN_NAME := main
BIN_PATH := $(DIST_DIR)/$(BIN_NAME)
ARTIFACT_NAME := prod.zip
ARTIFACT_PATH := $(DIST_DIR)/$(ARTIFACT_NAME)

FC_REGION := cn-shenzhen
FC_FUNCTION := autocerts
FC_API_PATH := /2023-03-30/functions/$(FC_FUNCTION)
FC_TIMEOUT := 600

OSS_BUCKET := default-dist-shenzhen
OSS_REGION := cn-shenzhen
OSS_OBJECT := autocerts/$(ARTIFACT_NAME)
OSS_URI := oss://$(OSS_BUCKET)/$(OSS_OBJECT)

.PHONY: test ut build dist cd-backend cd call-fc clean

test:
	go test ./...

ut: test

build:
	mkdir -p $(DIST_DIR)
	rm -f $(BIN_PATH) $(ARTIFACT_PATH)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BIN_PATH) ./main.go

dist: build
	cd $(DIST_DIR) && zip -j $(ARTIFACT_NAME) $(BIN_NAME)

cd-backend: dist
	@aliyun oss rm $(OSS_URI) --region $(OSS_REGION) || true
	@aliyun oss cp $(ARTIFACT_PATH) $(OSS_URI) --region $(OSS_REGION)
	@aliyun --region $(FC_REGION) fc PUT $(FC_API_PATH) --body '{"code":{"ossBucketName":"$(OSS_BUCKET)","ossObjectName":"$(OSS_OBJECT)"},"timeout":$(FC_TIMEOUT)}'

cd: test cd-backend

install: cd-backend
	go install ./cmd/autocerts

call-fc:
	go run ./cmd/autocerts $(ARGS)

clean:
	rm -rf $(DIST_DIR)
