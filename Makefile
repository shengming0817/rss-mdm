.PHONY: ci test t2
ci:
	python3 hack/ci.py

test:
	cargo test --locked --workspace --lib --bins --tests

t2:
	python3 hack/t2.py

.PHONY: source-t2 source-consumers
source-t2:
	python3 hack/source-t2.py

source-consumers:
	python3 hack/source-consumers.py
