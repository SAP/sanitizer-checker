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
# With debugger
#
# docker run -it --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined --entrypoint=/bin/bash semrep
#
# docker run -it -v $(pwd):/work/SemRep --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined --entrypoint=/bin/bash semrep-dev
#
FROM ubuntu:latest as semrep-dev

RUN apt-get update &&    \
    DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends install \
            build-essential \
            autoconf automake libtool \
            flex bison intltool \
            git libboost-all-dev \
            gdb

WORKDIR /work/MONA


#  https://github.com/cs-au-dk/MONA.git
RUN GIT_SSL_NO_VERIFY=true git clone https://github.wdf.sap.corp/i505600/mona.git . && \
    autoreconf -f -i && \
    ./configure 'CFLAGS=-O0 -g' && \
    make -j && make install && \
    cp BDD/bdd_external.h /usr/local/include/mona && \
    cp BDD/bdd_dump.h /usr/local/include/mona 

WORKDIR /work/LibStranger

RUN git clone https://github.com/vlab-cs-ucsb/LibStranger.git . && \
    chmod u+x autogen.sh && \
    ./autogen.sh && \
    ./configure 'CFLAGS=-O0 -g' && \
    make -j && make install

WORKDIR /work/SemRep

# The MONA header defines an function called export, which is a C++ keyword
RUN sed -i '1i#define export _export_' /usr/local/include/mona/bdd_external.h

FROM semrep-dev as semrep

WORKDIR /work/SemRep

COPY . .

WORKDIR /work/SemRep/SemRep

RUN autoreconf -f -i && \
    ./configure 'CXXFLAGS=-O0 -g' && \
    make clean && make -j

WORKDIR /work/run

ENV LD_LIBRARY_PATH /usr/local/lib

ENTRYPOINT ["/work/SemRep/SemRep/src/semrep"]
