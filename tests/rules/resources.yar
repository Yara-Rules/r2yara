import "r2"

rule resource {
	condition:
		for any i in ( 0..r2.number_of_resources ) : 
			(r2.resources[i].size > 2KB and 
			 r2.resources[i].type == "ICON" and
			 r2.resources[i].lang contains "JAPANESE")
}

rule resource_ss {
	condition:
		r2.resource("ICON", "LANG_JAPANESE")
}

rule resource_sr {
	condition:
		r2.resource("ICON", /japanese/i)
}

rule resource_rs {
	condition:
		r2.resource(/icon/i, "LANG_JAPANESE")
}

rule resource_rr {
	condition:
		r2.resource(/ICO/, /LANG_JAP/)
}