.PHONY: build release install-man clean

build:
	cargo build

release:
	cargo build --release

install-man:
	sh scripts/install_man.sh

clean:
	cargo clean
