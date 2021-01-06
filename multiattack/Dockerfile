FROM ubuntu:latest as multiattack

ENV TZ=Europe/Berlin
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

ENV SHELL /bin/bash

RUN apt-get update &&    \
    apt-get install -y   \
            python       \
	    python3      \
	    curl         \
            unzip        \
            zip          \
            autoconf2.13 \
            build-essential \
            autoconf \
            automake \
            libtool \
            flex \
            bison \
            intltool \
            git \
            libboost-all-dev


ARG SSH_KEY
ENV SSH_KEY=$SSH_KEY

# Make ssh dir
RUN mkdir "$HOME/.ssh/"
RUN echo "$SSH_KEY" > "$HOME/.ssh/id_rsa"
RUN chmod 600 "$HOME/.ssh/id_rsa"
RUN touch "$HOME/.ssh/known_hosts"
RUN ssh-keyscan github.com >> "$HOME/.ssh/known_hosts"
RUN ssh-keyscan git.ias.cs.tu-bs.de >> "$HOME/.ssh/known_hosts"

WORKDIR /work/MONA
RUN GIT_SSL_NO_VERIFY=true git clone gogs@git.ias.cs.tu-bs.de:Taintfox/mona.git . && \
    autoreconf -f -i && \
    ./configure 'CFLAGS=-O2 -march=native -g' && \
    make -j && make install && \
    cp BDD/bdd_external.h /usr/local/include/mona && \
    cp BDD/bdd_dump.h /usr/local/include/mona

WORKDIR /work/LibStranger

RUN GIT_SSL_NO_VERIFY=true git clone gogs@git.ias.cs.tu-bs.de:Taintfox/LibStranger.git . && \
    chmod u+x autogen.sh && \
    ./autogen.sh && \
    ./configure 'CFLAGS=-O2 -march=native -g' && \
    make -j && make install

ENV LD_LIBRARY_PATH /usr/local/lib

WORKDIR /work/SemRep

RUN GIT_SSL_NO_VERIFY=true git clone gogs@git.ias.cs.tu-bs.de:Taintfox/SemRep.git .

WORKDIR /work/SemRep/SemRep

RUN autoreconf -f -i && \
    ./configure 'CXXFLAGS=-O2 -march=native -g' && \
    make clean && make -j

WORKDIR /work/run

ENV LD_LIBRARY_PATH /usr/local/lib

ENTRYPOINT ["/work/SemRep/SemRep/src/multiattack"]
CMD ["--target", "/work/depgraphs", "--fieldname", "x", "--output", "/work/output"]

