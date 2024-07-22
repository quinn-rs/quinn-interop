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

Start by cloning the repository with its submodules:

``` sh
git clone --recursive git://github.com/quinn-rs/quinn-interop

```

### Using your machine

First, install the runner dependencies:

``` sh
pip3 install -r quic-interop-runner/requirements.txt
```

You will need some other dependencies on your system:
* tshark
* docker-compose

``` sh
# Build the container
docker build -f Dockerfile  -t stammw/quinn-interop:latest .

# Run the tests
cd quic-interop-runner/
python3 run.py -d -s quic-go -c quinn
```

### Using Vagrant

It's possible that your system doesn't handle the network correctly for the interop tester to work. In this case, a Vagrant box is available:

``` sh
# Spin up the vagrant box
vagrant up

# Then, connect to it and start testing
vagrant ssh
(cd ../ && docker build -f Dockerfile  -t stammw/quinn-interop:latest .) \
    && python3 run.py -d -s quic-go -c quinn
```

When you need to start hacking a bit, this command might be handy:

``` sh
vagrant rsync-auto
```
