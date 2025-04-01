.DEFAULT_GOAL := cas-server

BUILD_DIR=$(CURDIR)/build/bin
COMMIT=$(shell git rev-parse HEAD)
DATE=$(shell date)
TAG=$(shell git describe --tags)

LDFLAGS=-ldflags "-w -s -X 'main.gitCommit=$(COMMIT)' -X 'main.gitDate=$(DATE)' -X 'main.gitTag=$(TAG)'"

cas-server:
	@echo "Building target: $@" 
	go build $(LDFLAGS) -o $(BUILD_DIR)/$@ $(CURDIR)/main.go
	@echo "Done building."

clean:
	@rm -rf $(BUILD_DIR)/*

all: cas-server
