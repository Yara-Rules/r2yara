import "r2"

rule sections {
	condition:
		for any i in ( 0..r2.number_of_sections ) : 
			(r2.sections[i].size > 28KB and 
			 r2.sections[i].flags contains "r-x" and
			 r2.sections[i].name contains "text")
}