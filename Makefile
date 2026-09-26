.PHONY: build check ci ci-full ci-plan test t2 _t2
CI_BASE ?= origin/develop
CI_FULL ?= 0
CI_PLAN ?= 0
export CI_BASE CI_FULL CI_PLAN
ci:
	CI_PLAN=0 python3 hack/build_run.py -- python3 hack/ci.py

ci-full:
	CI_FULL=1 CI_PLAN=0 python3 hack/build_run.py -- python3 hack/ci.py

ci-plan:
	CI_PLAN=1 python3 hack/ci.py

build:
	python3 hack/build_run.py -- cargo build --locked --workspace

check:
	python3 hack/build_run.py -- cargo check --locked --workspace --all-targets

test:
	python3 hack/build_run.py -- cargo test --locked --workspace --lib --bins --tests

t2:
	python3 hack/build_run.py -- $(MAKE) -j1 --no-print-directory _t2

_t2:
	python3 hack/t2.py
	python3 hack/group-t2.py
	python3 hack/backend-t2.py
	python3 hack/publication-t2.py
	python3 hack/management-t2.py
	python3 hack/asset-t2.py
	python3 hack/compliance-t2.py
	python3 hack/command-t2.py
	python3 hack/task-t2.py
	python3 hack/apple-t2.py

.PHONY: source-t2
source-t2:
	python3 hack/build_run.py -- python3 hack/source-t2.py

.PHONY: t2-identity
t2-identity:
	python3 hack/build_run.py -- python3 hack/identity_t2.py

.PHONY: t2-group
t2-group:
	python3 hack/build_run.py -- python3 hack/group-t2.py

.PHONY: t2-backend t2-publication
t2-backend:
	python3 hack/build_run.py -- python3 hack/backend-t2.py
t2-publication:
	python3 hack/build_run.py -- python3 hack/publication-t2.py

.PHONY: t3-auth
t3-auth:
	python3 hack/auth_t3.py --candidate "$(MDM_CANDIDATE)" --tools-image "$(MDM_BROWSER_IMAGE)" --output "$(MDM_T3_OUTPUT)"

.PHONY: t2-assets
t2-assets:
	python3 hack/build_run.py -- python3 hack/asset-t2.py
.PHONY: command-catalog
command-catalog:
	python3 hack/build_run.py -- python3 hack/command_catalog.py --check

.PHONY: t2-tasks
t2-tasks:
	python3 hack/build_run.py -- python3 hack/task-t2.py

.PHONY: t2-apple
t2-apple:
	python3 hack/build_run.py -- python3 hack/apple-t2.py

.PHONY: t2-compliance
t2-compliance:
	python3 hack/build_run.py -- python3 hack/compliance-t2.py
