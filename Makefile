BINARY_DNS  = rpzd
BINARY_HTTP = rpzd-dashboard
BUILD_DIR   = bin
REMOTE_DIR  = /opt/rpzd
SYSTEMD     = /etc/systemd/system

# Set SERVER + SSH_PORT di .deploy.env atau via CLI.
# Contoh port non-default: make install SERVER=root@10.0.0.1 SSH_PORT=2222
SERVER   ?=
SSH_PORT ?= 22

SSH = ssh -p $(SSH_PORT)
SCP = scp -P $(SSH_PORT)

-include .deploy.env

.PHONY: build deploy install restart restart-dns restart-http

build:
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_DNS) ./cmd/rpzd/
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_HTTP) ./cmd/rpzd-dashboard/

# install — first-time full setup: build, upload, setup DB, generate config + TLS, start service.
# Opsi: DNS_ADDR (default 0.0.0.0:53), HTTP_ADDR (default 0.0.0.0:8080)
# Contoh: make install SERVER=root@10.0.0.1
#         make install SERVER=root@10.0.0.1 SSH_PORT=2222 HTTP_ADDR=0.0.0.0:8443
DNS_ADDR  ?= 0.0.0.0:53
HTTP_ADDR ?= 0.0.0.0:8080

install:
	@[ -n "$(SERVER)" ] || { echo "ERROR: SERVER tidak diset. Contoh: make install SERVER=root@10.0.0.1"; exit 1; }
	@echo "==> [1/4] Cek server: OS dan PostgreSQL..."
	$(SSH) $(SERVER) '\
		. /etc/os-release && \
		{ [ "$$ID" = "debian" ] && [ "$$VERSION_ID" = "13" ]; } || \
			{ echo "ERROR: Butuh Debian 13, terdeteksi: $$PRETTY_NAME"; exit 1; } && \
		echo "    OS: $$PRETTY_NAME OK" && \
		if ! command -v psql >/dev/null 2>&1; then \
			echo "    PostgreSQL tidak ada, menginstall..."; \
			apt-get update -qq && apt-get install -y -qq postgresql && \
			systemctl enable postgresql && systemctl start postgresql && \
			echo "    PostgreSQL terinstall."; \
		else \
			echo "    PostgreSQL sudah ada. OK"; \
		fi'
	@echo "==> [2/4] Build binary..."
	$(MAKE) --no-print-directory build
	@echo "==> [3/4] Upload binary + assets + service files..."
	$(SSH) $(SERVER) "mkdir -p $(REMOTE_DIR)/certs $(REMOTE_DIR)/data"
	$(SCP) $(BUILD_DIR)/$(BINARY_DNS)  $(SERVER):$(REMOTE_DIR)/$(BINARY_DNS).new
	$(SSH) $(SERVER) "mv $(REMOTE_DIR)/$(BINARY_DNS).new $(REMOTE_DIR)/$(BINARY_DNS)"
	$(SCP) $(BUILD_DIR)/$(BINARY_HTTP) $(SERVER):$(REMOTE_DIR)/$(BINARY_HTTP).new
	$(SSH) $(SERVER) "mv $(REMOTE_DIR)/$(BINARY_HTTP).new $(REMOTE_DIR)/$(BINARY_HTTP)"
	$(SCP) -r assets $(SERVER):$(REMOTE_DIR)/
	$(SCP) systemctl/rpzd.service          $(SERVER):$(SYSTEMD)/rpzd.service
	$(SCP) systemctl/rpzd-dashboard.service $(SERVER):$(SYSTEMD)/rpzd-dashboard.service
	$(SCP) scripts/setup.sh $(SERVER):$(REMOTE_DIR)/setup.sh
	@echo "==> [4/4] Setup DB, TLS, config, dan start service..."
	$(SSH) $(SERVER) "bash $(REMOTE_DIR)/setup.sh '$(DNS_ADDR)' '$(HTTP_ADDR)'"

# deploy — update binary + assets saja, tanpa menyentuh config/DB (untuk update rutin).
deploy: build
	@[ -n "$(SERVER)" ] || { echo "ERROR: SERVER tidak diset."; exit 1; }
	$(SSH) $(SERVER) "mkdir -p $(REMOTE_DIR)"
	$(SCP) $(BUILD_DIR)/$(BINARY_DNS)  $(SERVER):$(REMOTE_DIR)/$(BINARY_DNS).new
	$(SSH) $(SERVER) "mv $(REMOTE_DIR)/$(BINARY_DNS).new $(REMOTE_DIR)/$(BINARY_DNS)"
	$(SCP) $(BUILD_DIR)/$(BINARY_HTTP) $(SERVER):$(REMOTE_DIR)/$(BINARY_HTTP).new
	$(SSH) $(SERVER) "mv $(REMOTE_DIR)/$(BINARY_HTTP).new $(REMOTE_DIR)/$(BINARY_HTTP)"
	$(SCP) -r assets $(SERVER):$(REMOTE_DIR)/

# restart — deploy lalu restart kedua service.
restart: deploy
	$(SSH) $(SERVER) "systemctl restart rpzd rpzd-dashboard && sleep 5 && journalctl -u rpzd -u rpzd-dashboard --no-pager -n 20"

# restart-dns — restart DNS service saja (tanpa downtime dashboard).
restart-dns: deploy
	$(SSH) $(SERVER) "systemctl restart rpzd && sleep 3 && journalctl -u rpzd --no-pager -n 10"

# restart-http — restart dashboard saja (tanpa mengganggu DNS).
restart-http: deploy
	$(SSH) $(SERVER) "systemctl restart rpzd-dashboard && sleep 2 && journalctl -u rpzd-dashboard --no-pager -n 10"
