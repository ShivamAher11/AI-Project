FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc-mingw-w64-x86-64 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY evaluation/build-corpus.sh /usr/local/bin/build-corpus
RUN chmod 0755 /usr/local/bin/build-corpus
ENTRYPOINT ["/usr/local/bin/build-corpus"]
