#!/bin/bash

# Prerequisities
set -e

WORK=${PWD}
MONA_DIR=${WORK}/MONA
EXTRA_FLAGS=CFLAGS='-O0'


sudo apt-get update
DEBIAN_FRONTEND=noninteractive sudo apt-get -y --no-install-recommends install \
               build-essential \
               autoconf automake libtool \
               flex bison intltool \
               git libboost-all-dev \
               gdb

if [ -d "$MONA_DIR" ]; then
    echo "MONA Directory ${MONA_DIR} already exists, skipping checkout"
else
    git clone https://github.com/tmbrbr/MONA.git ${MONA_DIR}
fi

cd ${MONA_DIR}
autoreconf -f -i
./configure ${EXTRA_FLAGS}
make clean && make -j
sudo make install
sudo cp BDD/bdd_external.h /usr/local/include/mona && \
sudo cp BDD/bdd_dump.h /usr/local/include/mona 

cd ${WORK}/stranger
./autogen.sh
./configure ${EXTRA_FLAGS}
make clean && make -j
sudo make install

cd ${WORK}/semattack
autoreconf -f -i
./configure ${EXTRA_FLAGS}
make clean && make -j

