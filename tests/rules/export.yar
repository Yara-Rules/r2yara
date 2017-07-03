import "r2"

rule rule_export_ss
{
condition:
	r2.export("ADVAPI32.dll_WmiQuerySingleInstanceW", "FUNC")
}

rule rule_export_sr
{
condition:
	r2.export("ADVAPI32.dll_WmiQuerySingleInstanceW", /FUN/i)
}

rule rule_export_rs
{
condition:
	r2.export(/WmiQuerySingleInstanceW/, "FUNC")
}
rule rule_export_rr
{
condition:
	r2.export(/WmiQuerySingleInstance/, /fun/i)
}
