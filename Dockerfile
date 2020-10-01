FROM ubuntu:latest

RUN apt-get update &&    \
    DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends install \
            build-essential \
            autoconf automake libtool \
            flex bison intltool \
            git libboost-all-dev

WORKDIR /work/MONA

RUN git clone https://github.com/cs-au-dk/MONA.git . && \
    autoreconf -f -i && \
    ./configure && \
    make -j && make install && \
    cp BDD/bdd_external.h /usr/local/include/mona && \
    cp BDD/bdd_dump.h /usr/local/include/mona 
WORKDIR /work/LibStranger

RUN git clone https://github.com/vlab-cs-ucsb/LibStranger.git . && \
    chmod u+x autogen.sh && \
    ./autogen.sh && \
    ./configure && \
    make -j && make install

WORKDIR /work/SemRep

RUN sed -i '1i#define export _export_' /usr/local/include/mona/bdd_external.h


# docker build -t semrep .
# docker run -it --rm -v /mnt/workspace/stranger/SemRep:/work/SemRep --entrypoint="/bin/bash" semrep

