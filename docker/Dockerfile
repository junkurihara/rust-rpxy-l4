########################################
FROM --platform=$BUILDPLATFORM messense/rust-musl-cross:${TARGETARCH}-musl AS builder

LABEL maintainer="Jun Kurihara"

ARG TARGETARCH

RUN if [ $TARGETARCH = "amd64" ]; then \
  echo "x86_64" > /arch; \
  elif [ $TARGETARCH = "arm64" ]; then \
  echo "aarch64" > /arch; \
  else \
  echo "Unsupported platform: $TARGETARCH"; \
  exit 1; \
  fi

ENV CFLAGS=-Ofast

WORKDIR /tmp

COPY . /tmp/

ENV RUSTFLAGS="-C link-arg=-s"

RUN echo "Building rpxy-l4 from source" && \
  cargo update && \
  cargo build --release --target $(cat /arch)-unknown-linux-musl && \
  musl-strip --strip-all /tmp/target/$(cat /arch)-unknown-linux-musl/release/rpxy-l4 && \
  cp /tmp/target/$(cat /arch)-unknown-linux-musl/release/rpxy-l4 /tmp/target/release/rpxy-l4

########################################
FROM alpine:latest AS runner
LABEL maintainer="Jun Kurihara"

ENV RUNTIME_DEPS="logrotate ca-certificates su-exec"

RUN apk add --no-cache ${RUNTIME_DEPS} && \
  update-ca-certificates && \
  find / -type d -path /proc -prune -o -type f -perm /u+s -exec chmod u-s {} \; && \
  find / -type d -path /proc -prune -o -type f -perm /g+s -exec chmod g-s {} \; && \
  mkdir -p /rpxy-l4/bin &&\
  mkdir -p /rpxy-l4/log &&\
  mkdir -p /rpxy-l4/config

COPY --from=builder /tmp/target/release/rpxy-l4 /rpxy-l4/bin/rpxy-l4
COPY ./docker/run.sh /rpxy-l4
COPY ./docker/entrypoint.sh /rpxy-l4

RUN chmod +x /rpxy-l4/run.sh && \
  chmod +x /rpxy-l4/entrypoint.sh

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_DIR=/etc/ssl/certs

EXPOSE 80 443

CMD ["/rpxy-l4/entrypoint.sh"]

ENTRYPOINT ["/rpxy-l4/entrypoint.sh"]
