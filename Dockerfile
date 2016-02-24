FROM ubuntu:15.10

RUN apt-get update && apt-get install -y \
    python3.4 \
    python3-pip \
    clang \
    gcc \
    g++ \
    cmake \
    libcgroup-dev \
    git \
    sudo \
    acl

RUN git clone https://github.com/pzread/judge.git
RUN cd judge && \
    pip3 install -r requirements.txt && \
    mkdir lib && \
    cd lib && \
    cmake .. && \
    make
