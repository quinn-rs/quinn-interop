# Quinn interop

Interoperability container for [Quinn](https://github.com/quinn-rs/quinn), a `QUIC` implementation in pure Rust.

## Overview

This repository contains a server and client implementation to test interoperabilty with other `QUIC` and `HTTP/3` implementations. It also provides a container definition to be integrated to [QUIC interop runner]( https://github.com/marten-seemann/quic-interop-runner ), see the results [here](https://interop.seemann.io/).

You can find the container at DockerHub: [stammw / quinn-interop](https://hub.docker.com/repository/docker/stammw/quinn-interop)

## Directory summary:

* [submodule] quinn: the QUIC implementation
* [submodule] h3: the HTTP/3 implementation
* [submodule] quic-interop-runner: the testing application, to test locally
* quinn-interop: interop application to be deployed into the container

## Getting started

``` sh
# Clone the repository with its submodules
git clone --recursive git://github.com/stammw/quinn-interop

# Spin up the vagrant box
vagrant up

# Then, connect to it and start testing
vagrant ssh
(cd ../ && docker build -f Dockerfile  -t stammw/quinn-interop:latest .) \
    && python3 run.py -f downloaded -d  -s quic-go -c quinn
```

If you don't want to use vagrant, have a look in the Vagrantfile to have setup instruction.

When you need to start hacking a bit, this command might be handy:

``` sh
vagrant rsync-auto
```
