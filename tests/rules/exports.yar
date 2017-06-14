import "r2"
/*
rule rule_export_ssss
{
condition:
	r2.export("optind", "test", "obj.optind", "OBJECT")
}

rule rule_export_sssr
{
condition:
	r2.export("optind", "test", "obj.optind", /OBJECT/i)
}


rule rule_export_ssrs
{
condition:
	r2.export("optind", "test", /obj\.optind/, "OBJECT")
}
rule rule_export_ssrr
{
condition:
	r2.export("optind", "test", /obj\.optind/, /OBJECT/i)
}

rule rule_export_srss
{
condition:
	r2.export("optind", /test/, "obj.optind", "OBJECT")
}

rule rule_export_srsr
{
condition:
	r2.export("optind", /test/, "obj.optind", /OBJECT/i)
}

rule rule_export_srrs
{
condition:
	r2.export("optind", /test/, /obj\.optind/, "OBJECT")
}

rule rule_export_srrr
{
condition:
	r2.export("optind", /test/, /optind/, /OBJECT/)
}

rule rule_export_rsss
{
condition:
	r2.export(/optind/, "test", "obj.optind", "OBJECT")
}

rule rule_export_rssr
{
condition:
	r2.export(/optind/, "test", "obj.optind", /OBJECT/i)
}
*/
rule rule_export_rsrs
{
condition:
	r2.export(/optind/, "test", /obj\.optind/, "OBJECT")
}
/*

rule rule_export_rsrr
{
condition:
	r2.export(/optind/, "test", /obj\.optind/, /OBJECT/i)
}

rule rule_export_rrss
{
condition:
	r2.export(/optind/, /test/, "obj.optind", "OBJECT")
}

rule rule_export_rrsr
{
condition:
	r2.export(/optind/, /test/, "obj.optind", /OBJECT/i)
}

rule rule_export_rrrs
{
condition:
	r2.export(/optind/, /test/, /obj\.optind/, "OBJECT")
}

rule rule_export_rrrr
{
condition:
	r2.export(/optind/, /test/, /optind/, /OBJECT/)
}
*/