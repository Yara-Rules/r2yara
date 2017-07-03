import "r2"

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