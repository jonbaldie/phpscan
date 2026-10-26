.PHONY: setup build generate compile test cves lint package

setup:
	bash scripts/setup-bend.sh

build:
	bash scripts/build.sh

generate:
	bash scripts/build.sh generate

compile:
	bash scripts/build.sh compile

test:
	bash tests/check.sh ./dist/phpscan tests/cases/*.php tests/versions/*.php
	python3 tests/test_cli.py ./dist/phpscan
	python3 tests/test_advisories.py ./dist/phpscan
	python3 tests/test_symfony.py ./dist/phpscan
	python3 tests/test_install.py ./dist/phpscan
	python3 tests/test_docs.py

cves:
	bash tests/cve.sh ./dist/phpscan

lint:
	bash scripts/lint.sh

package:
	bash scripts/package.sh
