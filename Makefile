GO ?= go

.PHONY: test build clean

test:
	GO=$(GO) bash scripts/test.sh

build:
	GO=$(GO) bash scripts/build.sh

clean:
	rm -rf build dist
