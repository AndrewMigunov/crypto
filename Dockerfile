FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install --no-install-recommends --yes \
        build-essential \
        cmake \
        doxygen \
        gdb \
        git \
        graphviz \
        lcov \
        ninja-build \
        clang-format \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace/cryptomoon
