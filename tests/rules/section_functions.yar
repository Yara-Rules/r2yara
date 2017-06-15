import "r2"

rule rule_sections_ss
{
condition:
	r2.section(".note.ABI_tag","--r--")
}

rule rule_sections_sr
{
condition:
	r2.section(".note.gnu.build_id", /r/)
}

rule rule_sections_rs
{
condition:
	r2.section(/LOAD/, "m-r-x")
}

rule rule_sections_rr
{
condition:
	r2.section(/LOAD/, /x/)
}