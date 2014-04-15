LibStranger
========
LibStranger is an Automata-Based Symbolic String Analysis Library. You
can use LibStranger to solve string constraints and/or compute pre and
post-images of string manipulation operations such as concatenation and
replacement. It can handle complex regular-expression based replace
operations such as PHP's preg_replace and approximate these operations
in the presence of unbounded loops with high precision and smooth
performance. In addition, LibStranger provides fast and precise modeling
for common string functions such as trim, substring, toUpperCase and
toLowerCase and complex sanitization functions such as PHP's addslashes
and htmlspecialchars. LibStranger stands for STRing AutomatoN GEneratoR
Library.

Installation
============
LibStranger is a c library which means that you need to statically or dynamically link 
to it. This guide will assume that you have a c compiler installed on your machine such 
as gcc or clang. LibStranger also needs autotools to build it. To install these under
Ubuntu Linux run the following:
```bash
sudo apt-get install build-essential autoconf automake
```
LibStranger has been also tested under Mac OS X Mountain Lion and Mavericks.

LibStranger depends on [MONA library](http://www.brics.dk/mona/index.html) so you need to 
first download MONA, compile it and install it as following:
```bash
$> tar -xzvf mona-1.4-15.tar.gz
$> cd mona-1.4
$> ./configure
$> make
$> sudo make install
$> ls /usr/local/lib/libmona*
/usr/local/lib/libmonabdd.a         /usr/local/lib/libmonagta.a
/usr/local/lib/libmonabdd.la        /usr/local/lib/libmonagta.la
/usr/local/lib/libmonabdd.so        /usr/local/lib/libmonagta.so
/usr/local/lib/libmonabdd.so.1      /usr/local/lib/libmonagta.so.1
/usr/local/lib/libmonabdd.so.1.0.4  /usr/local/lib/libmonagta.so.1.0.4
/usr/local/lib/libmonadfa.a         /usr/local/lib/libmonamem.a
/usr/local/lib/libmonadfa.la        /usr/local/lib/libmonamem.la
/usr/local/lib/libmonadfa.so        /usr/local/lib/libmonamem.so
/usr/local/lib/libmonadfa.so.1      /usr/local/lib/libmonamem.so.1
/usr/local/lib/libmonadfa.so.1.0.4  /usr/local/lib/libmonamem.so.1.0.4
$> ls /usr/local/include/mona/
bdd.h     dfa.h       gnuc.h  mem.h
config.h  dlmalloc.h  gta.h
```
MONA will install four static/shared libraries under /usr/local/lib (by default). The
four library are: monabdd, monadfa, mondagta and monaamem.
MONA will also install a number of header files under /usr/local/include/mona (by default).
These are not enough. Make sure you copy the header files bdd\_external.h and 
bdd\_dump.h to /usr/local/include/mona in addition to other MONA header files there.
```bash
$> cd mona-1.4
$> sudo cp BDD/bdd_external.h /usr/local/include/mona
$> sudo cp BDD/bdd_dump.h /usr/local/include/mona
```

After that, clone LibStranger to your machine (or download the automatic zip file provided 
by github) 
```bash
$> mkdir LibStranger
$> cd LibStranger
$> git clone git@github.com:vlab-cs-ucsb/LibStranger.git .
$> ls
autogen.sh    COPYING      README.md  strangerlib.xcodeproj
configure.ac  makefile.am  src        testprogram
$> chmod u+x autogen.sh
$> ./autogen.sh
$> ls
aclocal.m4      build-aux    configure.ac  makefile.am  src
autogen.sh      config.h.in  COPYING       makefile.in  strangerlib.xcodeproj
autom4te.cache  configure    m4            README.md    testprogram
```
autogen.sh will create the GNU autotools files (i.e., configure script and makefiles) 
from the two manually written files, configure.ac and makefile.am. You need to have 
autoconf and automake installed on your machine.

Then we use the normal autotools installation system:
```bash
$> ./configure
$> make
$> sudo make install
$> ls /usr/local/lib/
libmonabdd.a         libmonadfa.so.1.0.4  libmonamem.so.1
libmonabdd.la        libmonagta.a         libmonamem.so.1.0.4
libmonabdd.so        libmonagta.la        libstranger.a
libmonabdd.so.1      libmonagta.so        libstranger.la
libmonabdd.so.1.0.4  libmonagta.so.1      libstranger.so
libmonadfa.a         libmonagta.so.1.0.4  libstranger.so.0
libmonadfa.la        libmonamem.a         libstranger.so.0.0.1
libmonadfa.so        libmonamem.la
libmonadfa.so.1      libmonamem.so
$> ls /usr/local/include/stranger
stranger.h
```
The output of the compilation will be a dynamic library called libstranger.so (or 
libstranger.dylib on Mac OS X). The library will be installed by default under
/usr/local/lib. It will also install the header file [stranger.h](src/stranger.h) 
under /usr/local/include/stranger. You need to include [stranger.h](src/stranger.h) 
in your program and link your program against LibStranger and MONA. If you need 
to get more involved with LibStranger you may need to include 
[stranger\_lib\_internal.h](src/stranger_lib_internal.h) and/or MONA header files.

Test & Usage
============
You can compile & run the simple test program [test_stranger.c](testprogram/test_stranger.c) 
that comes with LibStranger to test stranger library. Here is how to compile and 
run this program:
```bash
$> cd testprogram
$> gcc test_stranger.c -o test_stranger -l monabdd -l monadfa -l monamem -l stranger
$> sudo ldconfig
$> ./test_stranger
```
If you get a MONA invariant violation error message in make_basic.c then edit 
the mona file DFA/makebasic.c.
```c
#define MAX_EXCEPTION 50   /* change this to 2000. You can use a number as large number as you want */
#define MAX_VARIABLES 10   /* change this to 20. You can use 30 if you want. */
```

Read documentation in [stranger.h](src/stranger.h) to get an idea of LibStranger 
library interface and the different functions that can be called. You can look at 
[test_stranger.c](testprogram/test_stranger.c) for examples on how to use LibStranger 
to analyze C and PHP programs.
