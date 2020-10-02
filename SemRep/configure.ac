AC_INIT([semrep-pkg], [1.0])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])


AC_PROG_CXX
AC_PROG_CC
AC_PROG_RANLIB
AM_PROG_AR

AX_CXX_COMPILE_STDCXX_11(ext, mandatory)

AX_BOOST_BASE(1.48)
AX_BOOST_SYSTEM
AX_BOOST_FILESYSTEM
AX_BOOST_PROGRAM_OPTIONS
AX_BOOST_REGEX

AC_CHECK_HEADERS([stranger/stranger_lib_internal.h stranger/stranger.h] 
                 ,[],AC_MSG_ERROR(required Stranger library header file not found),[])

dnl ========== checks for libraries ========

AC_CHECK_LIB([monadfa], [dfaFree], [MONADFALIB=-lmonadfa], AC_MSG_ERROR(MONA DFA library not found))
# this will define a variable variable. you can use it in automake.am $(MONADFALIB)
AC_SUBST([MONADFALIB])

AC_CHECK_LIB([monabdd], [bdd_size], [MONABDDLIB=-lmonabdd], AC_MSG_ERROR(MONA BDD library not found))
AC_SUBST([MONABDDLIB])

AC_CHECK_LIB([monamem], [mem_alloc], [MONAMEMLIB=-lmonamem], AC_MSG_ERROR(MONA MEM library not found))
AC_SUBST([MONAMEMLIB])

AC_CHECK_LIB([m], [floor],[MLIB=-lm], AC_MSG_ERROR(c math library m not found))
AC_SUBST([MLIB])

AC_CHECK_LIB([stranger], [getVar], [STRANGERLIB=-lstranger], AC_MSG_ERROR(Stranger library not found))
AC_SUBST([STRANGERLIB])

AC_CONFIG_FILES([
  Makefile
  src/Makefile
  src/exceptions/Makefile
  src/depgraph/Makefile
])
AC_OUTPUT
