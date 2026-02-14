# Stage 1: build
FROM debian:bookworm AS builder
RUN apt-get update && apt-get install -y \
    cmake g++ pkg-config \
    libssl-dev libsqlcipher-dev libsodium-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . /src
RUN cmake -B /src/build -DCMAKE_BUILD_TYPE=Release -DSMP_DISABLE_TESTS=ON /src \
    && cmake --build /src/build --parallel

# Stage 2: runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    libssl3 libsqlcipher0 libsodium23 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/build/simplex-i2p-smp /usr/local/bin/
RUN mkdir -p /data

EXPOSE 5223
ENTRYPOINT ["simplex-i2p-smp"]
