REPOSITORY_ROOT := $(shell /usr/bin/dirname "$$(/usr/bin/git rev-parse --path-format=absolute --git-common-dir)")
CARGO_TARGET_DIR ?= $(REPOSITORY_ROOT)/target
export CARGO_TARGET_DIR

.PHONY: ci test t2
ci:
	python3 hack/ci.py

test:
	cargo test --locked --workspace --lib --bins --tests

t2:
	python3 hack/t2.py

.PHONY: t2-identity
t2-identity:
	python3 hack/identity_t2.py
