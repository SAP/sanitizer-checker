# Build and run the development environment:
#
# docker build --target semrep-dev -t semrep-dev .
#
# And the run with:
#
# docker run -it --rm -v /mnt/workspace/stranger/SemRep:/work/SemRep --entrypoint="/bin/bash" semrep-dev
#
# To build the command line container:
#
# docker build -t semrep .
#
# And run with:
#
# docker run -it --rm semrep
#
FROM ubuntu:latest as semrep-dev

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

# The MONA header defines an function called export, which is a C++ keyword
RUN sed -i '1i#define export _export_' /usr/local/include/mona/bdd_external.h

FROM semrep-dev as semrep

WORKDIR /work/SemRep

COPY . .

WORKDIR /work/SemRep/SemRep

RUN autoreconf -f -i && \
    ./configure && \
    make clean && make -j

ENV LD_LIBRARY_PATH /usr/local/lib

ENTRYPOINT ["/work/SemRep/SemRep/src/semrep"]
