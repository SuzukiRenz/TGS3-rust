FROM rust:1.88-bookworm AS build
WORKDIR /src
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/tg-s3-bot /usr/local/bin/tg-s3-bot
ENV DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/tg-s3-bot"]
CMD ["serve"]
