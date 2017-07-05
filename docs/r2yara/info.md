#Info


Rabin2 generates some information about the binary like compiled timestamp, if it has overlay or canary protection, the command used in r2 to extract this information is **iI**. The complete list of values is:

- havecode (integer)
- pic (integer)
- canary (integer)
- nx (integer)
- crypto (integer)
- va (integer)
- intrp (string)
- bintype (string)
- class (string)
- lang (string)
- arch (string)
- bits (integer)
- machine (integer)
- os (string)
- minopsz (integer)
- maxopsz (integer)
- pcalign (integer)
- subsys (string)
- endian (string)
- stripped (integer)
- static (integer)
- linenum (integer)
- lsyms (integer)
- relocs (integer)
- binsz (integer)
- rpath (string)
- compiled (string)
- dbg_file (string)
- guid (string)

Almost the parameters are auto-descriptived, so, with an example it's enough to undestand the parameters:

```
rule rule_info
{
condition:
	r2.info.havecode == 1 and 
	r2.info.pic == 0 and
	r2.info.canary == 1 and
	r2.info.nx == 1 and
	r2.info.crypto == 0 and
	r2.info.va == 1 and
	r2.info.intrp contains "linux-x86" and
	r2.info.bintype == "elf" and
	r2.info.class contains "ELF64" and
	r2.info.lang == "c" and
	r2.info.arch == "x86" and
	r2.info.bits == 64 and
    r2.info.machine == "AMD x86-64 architecture" and
    r2.info.os == "linux" and
    r2.info.minopsz == 1 and
    r2.info.maxopsz == 16 and
    r2.info.pcalign == 0 and
    r2.info.subsys == "linux" and
    r2.info.endian == "little" and
    r2.info.stripped == 1 and
    r2.info.static == 0 and
    r2.info.linenum == 0 and
    r2.info.lsyms == 0 and
    r2.info.relocs == 0 and
    r2.info.binsz > 100000 and
    r2.info.rpath == "NONE" and
    r2.info.compiled != "Sat Sep 9 11:32:42 2006" and
    r2.info.dbg_file not contains "test" and
    r2.info.guid == ""
}
```