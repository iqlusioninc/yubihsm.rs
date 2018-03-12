FROM centos:7.4.1708

# Install/update RPMs
RUN yum update -y && \
    yum groupinstall -y "Development Tools" && \
    yum install -y curl openssl-devel python centos-release-scl && \
    yum install -y llvm-toolset-7

# Enable llvm-toolset-7 in the shell environment
RUN bash -l -c "echo 'source scl_source enable llvm-toolset-7' > /etc/profile.d/llvm.sh"

# Install YubiHSM2 SDK
ENV YUBIHSM2_SDK_VERSION 1.0.1-centos7-amd64
RUN curl -O https://developers.yubico.com/YubiHSM2/Releases/yubihsm2-sdk-$YUBIHSM2_SDK_VERSION.tar.gz && \
    tar zxf yubihsm2-sdk-$YUBIHSM2_SDK_VERSION.tar.gz && \
    rm yubihsm2-sdk-$YUBIHSM2_SDK_VERSION.tar.gz && \
    cp -r yubihsm2-sdk/lib/* /usr/local/lib64/ && \
    cp -r yubihsm2-sdk/include/* /usr/local/include/ && \
    rm -r yubihsm2-sdk

ENV PATH "$PATH:/root/.cargo/bin"
ENV RUST_NIGHTLY_VERSION "nightly-2018-03-05"

# Install Rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
RUN rustup install $RUST_NIGHTLY_VERSION

RUN bash -l -c "echo $(rustc --print sysroot)/lib >> /etc/ld.so.conf"
RUN bash -l -c "echo /usr/local/lib64 >> /etc/ld.so.conf"
RUN ldconfig

ENV RUSTFMT_NIGHTLY_VERSION "0.4.0"
RUN rustup run $RUST_NIGHTLY_VERSION cargo install rustfmt-nightly --vers $RUSTFMT_NIGHTLY_VERSION --force

ENV CLIPPY_VERSION "0.0.187"
RUN rustup run $RUST_NIGHTLY_VERSION cargo install clippy --vers $CLIPPY_VERSION --force
