FROM python:3.12-slim

WORKDIR /app

COPY . .

RUN pip install -e ".[all]" && \
    rm -rf ~/.cache/pip

ENTRYPOINT ["reporeaver"]
CMD ["--help"]
