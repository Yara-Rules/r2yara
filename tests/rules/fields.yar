import "r2"

rule fields {
	condition:
		for any i in ( 0..r2.number_of_fields ) : 
			(r2.fields[i].name == "phdr_6" and
		 	 r2.fields[i].paddr	> 300KB)
}