import "r2"
rule rule_bins_si
{
condition:
	r2.bins("x86", 64)
}

rule rule_bins_ri
{
condition:
	r2.bins(/86/, 64)
}

rule rule_bins_ri_2
{
condition:
	r2.bins(/86/, -1)
}