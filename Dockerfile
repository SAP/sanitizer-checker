FROM ubuntu:latest as semrep

ENV TZ=Europe/Berlin
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

ENV SHELL /bin/bash

RUN apt-get -y update && DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends install sudo
	   
WORKDIR /work

COPY . .

RUN bash build.sh

ENV LD_LIBRARY_PATH /usr/local/lib

ENTRYPOINT ["/work/semattack/src/multiattack"]
CMD ["--target", "/work/depgraphs", "--fieldname", "x", "--output", "/work/output"]
