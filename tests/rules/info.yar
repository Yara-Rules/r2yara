import "r2"

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
    r2.info.compiled == "" and
    r2.info.dbg_file == "" and
    r2.info.guid == ""
}
