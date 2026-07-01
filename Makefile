.PHONY: setup certs webui webui-down test reset clean

setup:
	docker compose run --rm ssl-gen setup

certs:
	docker compose run --rm ssl-gen generate

webui:
	docker compose up --build -d webui
	@echo "Web UI started. Open https://$${WEBUI_BIND:-127.0.0.1}:$${WEBUI_PORT:-8443}"

webui-down:
	docker compose stop webui

test:
	docker compose run --rm ssl-gen test

reset:
	-docker compose stop webui 2>/dev/null
	docker compose run --rm --no-deps ssl-gen reset

clean: reset