FROM python:3.13-slim

WORKDIR /app

# pip builds from this copy, which has no .git, so setuptools-scm would fall
# back to 0.1.0; the release workflow passes the tag as VERSION.
ARG VERSION=0.0.0
COPY pyproject.toml ./
COPY pico_auth ./pico_auth
RUN SETUPTOOLS_SCM_PRETEND_VERSION_FOR_PICO_AUTH=${VERSION} pip install --no-cache-dir .

COPY application.yaml .

EXPOSE 8100
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8100/.well-known/openid-configuration', timeout=2)"

CMD ["python", "-m", "pico_auth.main"]
