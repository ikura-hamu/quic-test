# syntax=docker/dockerfile:1
FROM debian:bookworm-slim AS build
ARG TARGETARCH
ARG MSQUIC_VERSION=2.6.4
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates cmake curl g++ libnuma1 libssl3 \
    && rm -rf /var/lib/apt/lists/*
RUN --mount=type=secret,id=build_ca_bundle \
    set -eux; \
    if [ -f /run/secrets/build_ca_bundle ]; then export CURL_CA_BUNDLE=/run/secrets/build_ca_bundle; fi; \
    case "${TARGETARCH}" in \
      amd64) checksum=c81352050683672eca2a7794c8129da73caca1556b1ce1ff2b7784dd24897227 ;; \
      arm64) checksum=8d0af94f1a42926ff952999da24203a3a7f96a24cd5690cc52e851e93acde865 ;; \
      *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    package="libmsquic_${MSQUIC_VERSION}_${TARGETARCH}.deb"; \
    curl -fSL --retry 3 "https://packages.microsoft.com/debian/12/prod/pool/main/libm/libmsquic/${package}" -o "/tmp/${package}"; \
    echo "${checksum}  /tmp/${package}" | sha256sum -c -; \
    dpkg-deb --extract "/tmp/${package}" /msquic; \
    rm /msquic/usr/lib/*/libmsquic.lttng.so.*; \
    mkdir /msquic/include; \
    cd /msquic/include; \
    for header in msquic.h msquic_posix.h quic_sal_stub.h; do \
      curl -fSL --retry 3 "https://raw.githubusercontent.com/microsoft/msquic/v${MSQUIC_VERSION}/src/inc/${header}" -o "${header}"; \
    done; \
    echo '3ebde22085df627140fd6208c638a9a3cd7dd3da9bd270f64f022b1c46b1bc4f  msquic.h' | sha256sum -c -; \
    echo 'a0e11c5eb1a4bbd5e18e4f7a381dd024064df2ee76ed555b49c0b8a66c15f526  msquic_posix.h' | sha256sum -c -; \
    echo '8849135a95fee2a49373e168c12a89380de46e23c2136e6b0597394d09a9614c  quic_sal_stub.h' | sha256sum -c -
WORKDIR /build
COPY CMakeLists.txt ./
COPY src/ src/
RUN cmake -S . -B out -DCMAKE_BUILD_TYPE=Release \
      -DMSQUIC_INCLUDE_DIR=/msquic/include \
      -DMSQUIC_LIBRARY="$(find /msquic/usr/lib -name libmsquic.so.2)" \
    && cmake --build out --parallel \
    && strip out/quic-server out/quic-client

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libnuma1 libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir /certs
COPY --from=build /msquic/usr/lib/ /usr/lib/
RUN ldconfig
USER 65532:65532

FROM runtime AS client
COPY --from=build /build/out/quic-client /usr/local/bin/quic-client
ENTRYPOINT ["/usr/local/bin/quic-client"]

FROM runtime AS server
COPY --from=build /build/out/quic-server /usr/local/bin/quic-server
EXPOSE 4433/udp
ENTRYPOINT ["/usr/local/bin/quic-server"]
