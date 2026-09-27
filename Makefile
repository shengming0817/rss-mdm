.PHONY: build check test ci ci-full ci-plan t2 dev t3-auth
CI_BASE ?= origin/develop
SUITE ?= affected
ACTION ?= status
MODE ?= host
DEV_ARGS ?=
export CI_BASE
ci:
	CI_PLAN=0 CI_T2=none python3 hack/build_run.py -- python3 hack/ci.py
ci-full:
	CI_FULL=1 CI_PLAN=0 CI_T2=all python3 hack/build_run.py -- python3 hack/ci.py
ci-plan:
	CI_PLAN=1 CI_T2=none python3 hack/ci.py
build:
	python3 hack/build_run.py -- cargo build --locked --workspace
check:
	python3 hack/build_run.py -- cargo check --locked --workspace --all-targets
test:
	python3 hack/build_run.py -- cargo test --locked --workspace --lib --bins --tests
t2:
	python3 hack/build_run.py -- python3 hack/t2.py --suite "$(SUITE)" --base "$(CI_BASE)"
dev:
	python3 hack/build_run.py -- python3 hack/t2_environment.py "$(ACTION)" --mode "$(MODE)" $(DEV_ARGS)
t3-auth:
	python3 hack/auth_t3.py $(T3_ARGS)
