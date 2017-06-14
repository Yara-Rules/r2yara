import "r2"


rule rule_import_isss_1
{
condition:
	r2.imports(1, "GLOBAL", "FUNC", "__ctype_toupper_loc")
}
rule rule_import_isss_2
{
condition:
	not r2.imports(5, "GLOBAL", "FUNC", "__ctype_toupper_loc")
}


rule rule_import_ssr
{
condition:
	r2.imports(1, "GLOBAL", "FUNC", /ctype_toupper/i)
}

rule rule_import_srs
{
condition:
	r2.imports(1, "GLOBAL", /FUNC/, "__ctype_toupper_loc")
}

rule rule_import_srr
{
condition:
	r2.imports(1, "GLOBAL", /UNC/, /ctype_toupper/)
}

rule rule_import_rss
{
condition:
	r2.imports(-1, /LOBAL/i, "FUNC", "__ctype_toupper_loc")
}


rule rule_import_rsr
{
condition:
	r2.imports(1, /LOBAL/, "FUNC", /ctype_toupper/)
}

rule rule_import_rrs
{
condition:
	r2.imports(1, /LOBAL/, /FUNC/, "__ctype_toupper_loc")
}

rule rule_import_rrr
{
condition:
	r2.imports(1, /LOBAL/, /FUNC/, /TOUPPER/i)
}