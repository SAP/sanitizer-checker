# Running Multiattack

How to (simply) reproduce the analysis on different machines.

## Building the docker container

```bash
docker build -t multiattack --build-arg SSH_KEY="$(cat ~/.ssh/id_rsa)" --no-cache .
```

This command works on the Taintfox PC. To build it elsewhere you have to substitute a SSH key with read permissions to the TUBS Taintfox Organisation, namely the MONA, LibStranger and SemRep Repositories.

The ``--no-cache`` flag is required as Docker does pick up changes to the git repositories.


## Running it

```bash
docker run -v /home/taintfox/depgraphs_all:/work/depgraphs -v /home/taintfox/analysis/out:/work/output multiattack
```

The folder mapped to ``/work/depgraps`` contains the input files and multiattack writes the results to the folder mapped onto ``/work/output``.

The output folder gets fairly big if large amounts of data are analyzed. 9GB of dependency graphs yield 4.4GB of results but your mileage may vary...
