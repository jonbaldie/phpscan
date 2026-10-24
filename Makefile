.PHONY: setup build test cves lint package

setup:
	bash scripts/setup-bend.sh

build:
	bash scripts/build.sh

test:
	bash tests/check.sh ./dist/phpscan tests/cases/*.php tests/versions/*.php
	python3 tests/test_cli.py ./dist/phpscan
	python3 tests/test_install.py ./dist/phpscan

cves:
	bash tests/cve.sh ./dist/phpscan

lint:
	bash scripts/lint.sh

package:
	bash scripts/package.sh
