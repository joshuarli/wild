# syntax=docker/dockerfile:1.7
# Native Linux ARM64 benchmark toolchain. Source checkouts stay read-only host mounts; the
# benchmark wrapper puts every writable Cargo, compiler, and report path below /cache.
FROM rust:1.97.1-alpine

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN apk add --no-cache \
        bash \
        build-base \
        clang \
        curl-static \
        git \
        libgit2-dev \
        libgit2-static \
        lld \
        nghttp2-dev \
        openssl-dev \
        openssl-libs-static \
        perl \
        pkgconf \
        python3 \
        time \
        zlib-dev \
        zlib-static \
    && rustup toolchain install nightly-2026-07-24 --profile minimal \
        --component rust-src \
        --component llvm-tools-preview
