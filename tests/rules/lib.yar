import "r2"

rule rule_lib_s
{
condition:
	r2.lib("libselinux.so.1")
}

rule rule_lib_r
{
condition:
	r2.lib(/selinux/)
}

