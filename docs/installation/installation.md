These instructions detailed the steps to install al the requirements to use this module.

# Install radare2
The first step is download & install radare2:

```sh
git clone https://github.com/radare/radare2
cd radare2
sys/install.sh   # just run this script to update r2 from git
```

# Download Yara
You must download the last version of Yara from GitHub:

[https://github.com/VirusTotal/yara/releases](https://github.com/VirusTotal/yara/releases)

and uncompress for instance in your home folder (/home/user/yara)

# Integrate r2yara inside Yara
This is the "complicated" part of the installation, you need to include the file r2.c inside Yara, modify some files and compile all. But better step by step:

1. Download r2.c from our repo [https://github.com/Yara-Rules/r2yara/blob/master/r2.c](https://github.com/Yara-Rules/r2yara/blob/master/r2.c) to libyara/modules/
2. Modify "libyara/modules/module_list" and add r2 module in the Cuckoo block. The file should look similar to:

```
MODULE(pe)
MODULE(elf)
MODULE(math)

#ifdef CUCKOO
MODULE(cuckoo)
MODULE(r2)
#endif
```

3. Modify "libyara/Makefile.am" to add r2 module in the Cuckoo block:

```
MODULES =  modules/tests.c
MODULES += modules/pe.c
[...]

if CUCKOO_MODULE
MODULES += modules/cuckoo.c
MODULES += modules/r2.c
endif
```

4. Define the simbol DOLLAR_SIGN in file "configure.ac", at the end of file:
```
#Just before AC_OUTPUT
AC_SUBST([DOLLAR_SIGN],[$])

AC_OUTPUT
```

5. Modify "libyara/Makefile.am" to include the flags to compile with r2pipe:

```
AM_CFLAGS=-O3 -Wall -Wno-deprecated-declarations -std=gnu99 -I$(srcdir)/include
#Just after the declaration of AM_CFLAGS include this:

AM_CFLAGS+=@DOLLAR_SIGN@(shell pkg-config --cflags r_socket)
LIBS += @DOLLAR_SIGN@(shell pkg-config --libs r_socket)
```

6. Include more flags in "Makefile.am", just in the end of file:
```
AM_CFLAGS += @DOLLAR_SIGN@(shell pkg-config --cflags r_socket)
LIBS += @DOLLAR_SIGN@(shell pkg-config --libs r_socket)
```

7. Compile Yara...
```sh
./bootstrap.sh
./configure --enable-cuckoo
make
sudo make install
```

8. Enjoy!
```sh
cd r2yara_folder && ./launch_tests.py
```
