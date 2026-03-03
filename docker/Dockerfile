# Shared arguments for both builder and runner stages
ARG BUILD_ARTIFACTS=/tmp/target

########################################
FROM --platform=$BUILDPLATFORM messense/rust-musl-cross:${TARGETARCH}-musl AS builder

LABEL maintainer="Jun Kurihara"

ARG TARGETARCH
ARG BUILD_ARTIFACTS
ARG CARGO_TARGET_CACHE=/tmp/cargo-target-cache

ARG CFLAGS=-Ofast
ARG RUSTFLAGS="-C link-arg=-s"

RUN if [ $TARGETARCH = "amd64" ]; then \
  echo "x86_64" > /arch; \
  elif [ $TARGETARCH = "arm64" ]; then \
  echo "aarch64" > /arch; \
  else \
  echo "Unsupported platform: $TARGETARCH"; \
  exit 1; \
  fi

WORKDIR /tmp

RUN --mount=type=bind,target=. \
  --mount=type=cache,target=/root/.cargo/registry,sharing=locked \
  --mount=type=cache,target=/root/.cargo/git,sharing=locked \
  --mount=type=cache,target=${CARGO_TARGET_CACHE},sharing=locked \
  echo "Building rpxy-l4 from source" && \
  cargo build --release --package rpxy-l4 --target $(cat /arch)-unknown-linux-musl --target-dir ${CARGO_TARGET_CACHE} && \
  cp ${CARGO_TARGET_CACHE}/$(cat /arch)-unknown-linux-musl/release/rpxy-l4 ${BUILD_ARTIFACTS}/release/rpxy-l4 && \
  musl-strip --strip-all ${BUILD_ARTIFACTS}/release/rpxy-l4

########################################
FROM alpine:latest AS runner

LABEL maintainer="Jun Kurihara"

ARG BUILD_ARTIFACTS
ARG RUNTIME_DEPS="logrotate ca-certificates su-exec"

RUN apk add --no-cache ${RUNTIME_DEPS} && \
  update-ca-certificates && \
  find / -type d -path /proc -prune -o -type f -perm /u+s -exec chmod u-s {} \; && \
  find / -type d -path /proc -prune -o -type f -perm /g+s -exec chmod g-s {} \; && \
  mkdir -p /rpxy-l4/bin &&\
  mkdir -p /rpxy-l4/log &&\
  mkdir -p /rpxy-l4/config

COPY --from=builder ${BUILD_ARTIFACTS}/release/rpxy-l4 /rpxy-l4/bin/rpxy-l4
COPY ./docker/run.sh /rpxy-l4
COPY ./docker/entrypoint.sh /rpxy-l4

RUN chmod +x /rpxy-l4/run.sh && \
  chmod +x /rpxy-l4/entrypoint.sh

# Set environment variables for SSL certificates used in runtime
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_DIR=/etc/ssl/certs

EXPOSE 80 443

CMD ["/rpxy-l4/entrypoint.sh"]

ENTRYPOINT ["/rpxy-l4/entrypoint.sh"]
