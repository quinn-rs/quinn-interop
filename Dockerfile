FROM rust:1.57 as build

WORKDIR /build

COPY h3/ h3
COPY quinn-interop/ quinn-interop

RUN cargo build --release --manifest-path quinn-interop/Cargo.toml

FROM martenseemann/quic-network-simulator-endpoint:latest as h3-quinn-interop

WORKDIR /h3-quinn

COPY --from=build \
     /build/quinn-interop/target/release/client \
     /build/quinn-interop/target/release/server \
     ./

COPY --from=build /build/quinn-interop/run_endpoint.sh /

#ENV RUST_LOG=h3=trace,server=trace
ENV RUST_LOG=server=info,client=info
ENV RUST_BACKTRACE=1

ENTRYPOINT [ "/run_endpoint.sh" ]
