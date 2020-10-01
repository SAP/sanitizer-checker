SUBDIRS = depgraph exceptions
noinst_LIBRARIES = libsemrep.a
libsemrep_a_SOURCES = ImageComputer.cpp  PerfInfo.cpp  RegExp.cpp  SemRepair.cpp  SemRepairDebugger.cpp  StrangerAutomaton.cpp

bin_PROGRAMS = semrep
semrep_SOURCES = main.cpp
semrep_LDADD = libsemrep.a \
               $(STRANGERLIB) \
               $(MONADFALIB) \
               $(MONABDDLIB) \
               $(BOOST_REGEX_LIB) \
               $(BOOST_IO_STREAMS_LIB) \
               $(BOOST_PROGRAM_OPTIONS_LIB) \
               $(BOOST_FILESYSTEM_LIB) \
               $(BOOST_SYSTEM_LIB) \
               depgraph/libdepgraph.a \
               exceptions/libexceptions.a
