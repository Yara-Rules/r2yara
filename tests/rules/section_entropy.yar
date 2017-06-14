import "r2"
import "math"

rule rule_sections_entropy_s
{
	condition:
		for any i in ( 0..r2.number_of_sections ) : 
				(r2.sections[i].name contains "note.ABI_tag" and 
				 math.entropy(r2.sections[i].paddr, r2.sections[i].size) > 1.5)
}
