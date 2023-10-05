TARGET := ebpf-hook-ifunc
ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))

all: build copy
.PHONY: all build copy

build:
	@cargo build -r

copy:
	cp ./target/release/ebpf-hook-ifunc .

run: build copy
	sudo ./ebpf-hook-ifunc ${ARGS}