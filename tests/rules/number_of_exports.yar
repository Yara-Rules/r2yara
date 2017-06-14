import "r2"

rule rule_number_of_exports
{
	condition:
		r2.number_of_exports > 3
}
