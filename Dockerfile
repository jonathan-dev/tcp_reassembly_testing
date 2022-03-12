From archlinux:latest
COPY . /home/

RUN pacman -Sy go gcc make cmake python2 python3 git boost glibc --noconfirm
RUN python2 -m ensurepip
RUN pacman -S wireshark-cli --noconfirm

# RUN apk --no-cache add go 
# # Install rust
# RUN apk --no-cache add clang lld curl
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain nightly -y
RUN source $HOME/.cargo/env
# 
# RUN apk add --no-cache git make cmake python2-dev python2 && \
# 	python2 -m ensurepip 
# RUN apk add --no-cache libpcap-dev
# RUN apk add clang

