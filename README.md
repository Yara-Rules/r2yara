Hemos usado la última respuesta para añadir las librerías de R2 al makefile (only as reminder):
http://stackoverflow.com/questions/15711824/autoreconf-stops-with-non-posix-variable-name


#Para compilar Yara con R2 (framework):
En el archivo configure.ac añadimos esta línea:
AC_SUBST([DOLLAR_SIGN],[$])

En el archivo Makefile.am añadimos estas líneas:
AM_CFLAGS += @DOLLAR_SIGN@(shell pkg-config --cflags r_socket)
LIBS+=@DOLLAR_SIGN@(shell pkg-config --libs r_socket)



En el archivo libyara/Makefile.am añadimos esta línea:
AM_CFLAGS+=@DOLLAR_SIGN@(shell pkg-config --cflags r_socket)
LIBS += @DOLLAR_SIGN@(shell pkg-config --libs r_socket)

