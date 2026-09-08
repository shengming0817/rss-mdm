.PHONY: ci test t2
ci:
	python3 hack/ci.py

test:
	cargo test --locked --test model

t2:
	python3 hack/t2.py
