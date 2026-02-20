FROM python:3.13-slim
WORKDIR /app
RUN pip install --no-cache-dir pico-auth
COPY application.yaml .
EXPOSE 8100
CMD ["python", "-m", "pico_auth.main"]
