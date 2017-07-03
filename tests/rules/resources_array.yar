import "r2"

rule resources {
	condition:
		for any i in ( 0..r2.number_of_resources ) : 
			(r2.resources[i].size > 2KB and 
			 r2.resources[i].type == "ICON" and
			 r2.resources[i].lang contains "JAPANESE")
}
