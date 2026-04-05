# bulwark Makefile — convenience targets for common tasks

PREFIX      ?= /usr/local
BIN_DIR     ?= $(PREFIX)/bin
CONFIG_DIR  ?= /etc/bulwark
SYSTEMD_DIR ?= /etc/systemd/system
DOC_DIR     ?= $(PREFIX)/share/doc/bulwark

CARGO       ?= cargo

.PHONY: all help build release install uninstall test fuzz clean fmt clippy doc check run service-enable service-disable service-status

all: build

help:
	@echo "bulwark — network security daemon for open WiFi"
	@echo ""
	@echo "Targets:"
	@echo "  build           - Build debug binary"
	@echo "  release         - Build optimized release binary"
	@echo "  install         - Install binary, config, systemd unit (requires root)"
	@echo "  uninstall       - Remove installed files (requires root)"
	@echo "  test            - Run the full test suite"
	@echo "  fuzz            - Build fuzz targets (requires cargo-fuzz + nightly)"
	@echo "  fmt             - Format code"
	@echo "  clippy          - Run clippy lints"
	@echo "  doc             - Build and open rustdoc"
	@echo "  check           - Validate the example config"
	@echo "  run             - Run in foreground (requires root)"
	@echo "  clean           - Remove build artifacts"
	@echo ""
	@echo "Service management (after install):"
	@echo "  service-enable  - systemctl enable --now bulwark"
	@echo "  service-disable - systemctl disable --now bulwark"
	@echo "  service-status  - systemctl status bulwark"

build:
	$(CARGO) build

release:
	$(CARGO) build --release

install: release
	@if [ "$$(id -u)" -ne 0 ]; then echo "error: 'make install' requires root"; exit 1; fi
	install -m 755 -D target/release/bulwark $(BIN_DIR)/bulwark
	install -m 644 -D bulwark.service $(SYSTEMD_DIR)/bulwark.service
	@if [ ! -f $(CONFIG_DIR)/bulwark.toml ]; then \
		install -m 644 -D bulwark.toml $(CONFIG_DIR)/bulwark.toml; \
		echo "installed default config to $(CONFIG_DIR)/bulwark.toml"; \
	else \
		install -m 644 -D bulwark.toml $(CONFIG_DIR)/bulwark.toml.example; \
		echo "config exists, installed example to $(CONFIG_DIR)/bulwark.toml.example"; \
	fi
	install -m 644 -D README.md $(DOC_DIR)/README.md
	install -m 644 -D SECURITY.md $(DOC_DIR)/SECURITY.md
	-install -m 644 -D EXAMPLES.md $(DOC_DIR)/EXAMPLES.md
	install -m 644 -D LICENSE $(DOC_DIR)/LICENSE
	systemctl daemon-reload
	@echo ""
	@echo "  bulwark installed. Try:"
	@echo "    sudo bulwark --foreground"
	@echo "    sudo systemctl enable --now bulwark"

uninstall:
	@if [ "$$(id -u)" -ne 0 ]; then echo "error: 'make uninstall' requires root"; exit 1; fi
	-systemctl stop bulwark.service 2>/dev/null
	-systemctl disable bulwark.service 2>/dev/null
	rm -f $(BIN_DIR)/bulwark
	rm -f $(SYSTEMD_DIR)/bulwark.service
	rm -rf $(DOC_DIR)
	systemctl daemon-reload
	@echo "bulwark uninstalled (config at $(CONFIG_DIR) preserved)"

test:
	$(CARGO) test

fuzz:
	cd fuzz && $(CARGO) +nightly fuzz build

fmt:
	$(CARGO) fmt

clippy:
	$(CARGO) clippy -- -D warnings

doc:
	$(CARGO) doc --no-deps --open

check: release
	./target/release/bulwark --check-config --config bulwark.toml

run: release
	@if [ "$$(id -u)" -ne 0 ]; then echo "error: 'make run' requires root for full functionality"; fi
	sudo ./target/release/bulwark --foreground --config bulwark.toml

clean:
	$(CARGO) clean

service-enable:
	systemctl enable --now bulwark

service-disable:
	systemctl disable --now bulwark

service-status:
	systemctl status bulwark
