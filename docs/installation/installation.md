These instructions detailed the steps to install al the requirements to use this module.

# Radare2
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

- Download r2.c from our repo [https://github.com/plutec/r2yara/r2.c](https://github.com/plutec/r2yara/r2.c) to libyara/modules/
- Modify "libyara/modules/module_list" and add r2 module in the Cuckoo block. The file should look similar to:

```
MODULE(pe)
MODULE(elf)
MODULE(math)

#ifdef CUCKOO
MODULE(cuckoo)
MODULE(r2)
#endif
```

- Modify "libyara/Makefile.am" to add r2 module in the Cuckoo block:

```
MODULES =  modules/tests.c
MODULES += modules/pe.c
[...]

if CUCKOO_MODULE
MODULES += modules/cuckoo.c
MODULES += modules/r2.c
endif
```

- TODO More steps

Recompile Yara, with cuckoo module enabled. The reason to include it is because Cuckoo module uses libjansson like r2 (and other modules like androguard), and this is the easy way to prepare all dependencies. If you don't want to include cuckoo module, you have to browse for all Makefile files and include libjansson without condition (this is the very hard way). 

```
./bootstrap.sh
./configure --enable-cuckoo
make
make install
```