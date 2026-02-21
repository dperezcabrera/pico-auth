.PHONY: $(VERSIONS) build-% test-% test-all client-wheel clean

VERSIONS = 3.11 3.12 3.13 3.14

CLIENT_AUTH_DIR = ../pico-client-auth
WHEEL_DIR = pico_client_auth_wheel


client-wheel:
	rm -rf $(WHEEL_DIR)
	mkdir -p $(WHEEL_DIR)
	cd $(CLIENT_AUTH_DIR) && pip wheel --no-deps -w ../pico-auth/$(WHEEL_DIR) .

build-%: client-wheel
	DOCKER_BUILDKIT=1 docker build --build-arg PYTHON_VERSION=$* \
		-t pico_auth-test:$* --no-cache -f Dockerfile.test .

test-%: build-%
	docker run --rm pico_auth-test:$*

test-all: $(addprefix test-, $(VERSIONS))
	@echo "All versions done"

clean:
	rm -rf $(WHEEL_DIR)
