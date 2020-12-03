SUBDIRS = depgraph exceptions
AM_LIBS = @PTHREAD_LIBS@ @LIBS@
AM_CFLAGS = @CFLAGS@ @PTHREAD_CFLAGS@
AM_CC = @PTHREAD_CC@
noinst_LIBRARIES = libsemrep.a
libsemrep_a_SOURCES = ImageComputer.cpp \
                      PerfInfo.cpp \
                      RegExp.cpp \
                      SemRepair.cpp \
                      SemRepairDebugger.cpp \
                      StrangerAutomaton.cpp \
                      SemAttack.cpp \
                      SemAttackBw.cpp \
                      AttackPatterns.cpp \
                      AutomatonGroups.cpp \
                      MultiAttack.cpp \
                      AttackContext.cpp \
                      ValidationImageComputer.cpp \
		      AnalysisResult.cpp

bin_PROGRAMS = semrep semattack semattack_bw multiattack

semrep_SOURCES = main.cpp
semrep_LDADD = libsemrep.a \
               depgraph/libdepgraph.a \
               exceptions/libexceptions.a \
               $(MONADFALIB) \
               $(MONABDDLIB) \
               $(STRANGERLIB) \
               $(BOOST_IO_STREAMS_LIB) \
               $(BOOST_PROGRAM_OPTIONS_LIB) \
               $(BOOST_FILESYSTEM_LIB) \
               $(BOOST_SYSTEM_LIB) \
               $(BOOST_REGEX_LIB) \
               $(BOOST_THREAD_LIB) \
               @PTHREAD_CFLAGS@

semattack_SOURCES = main_attack.cpp
semattack_LDADD = libsemrep.a \
                 depgraph/libdepgraph.a \
                 exceptions/libexceptions.a \
                 $(MONADFALIB) \
                 $(MONABDDLIB) \
                 $(STRANGERLIB) \
                 $(BOOST_IO_STREAMS_LIB) \
                 $(BOOST_PROGRAM_OPTIONS_LIB) \
                 $(BOOST_FILESYSTEM_LIB) \
                 $(BOOST_SYSTEM_LIB) \
                 $(BOOST_REGEX_LIB)

semattack_bw_SOURCES = main_attack_bw.cpp
semattack_bw_LDADD = libsemrep.a \
                 depgraph/libdepgraph.a \
                 exceptions/libexceptions.a \
                 $(MONADFALIB) \
                 $(MONABDDLIB) \
                 $(STRANGERLIB) \
                 $(BOOST_IO_STREAMS_LIB) \
                 $(BOOST_PROGRAM_OPTIONS_LIB) \
                 $(BOOST_FILESYSTEM_LIB) \
                 $(BOOST_SYSTEM_LIB) \
                 $(BOOST_REGEX_LIB)

multiattack_SOURCES = main_multi_attack.cpp
multiattack_LDADD = libsemrep.a \
                 depgraph/libdepgraph.a \
                 exceptions/libexceptions.a \
                 $(MONADFALIB) \
                 $(MONABDDLIB) \
                 $(STRANGERLIB) \
                 $(BOOST_IO_STREAMS_LIB) \
                 $(BOOST_PROGRAM_OPTIONS_LIB) \
                 $(BOOST_FILESYSTEM_LIB) \
                 $(BOOST_SYSTEM_LIB) \
                 $(BOOST_REGEX_LIB) \
                 $(BOOST_THREAD_LIB) \
                 @PTHREAD_CFLAGS@
