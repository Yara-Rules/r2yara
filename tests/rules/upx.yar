import "r2"

rule UPX {
	condition: true
}
rule UPX2 {
	strings:
		$upx = "UPX"
	condition:
		r2.section("UPX0", "") and
		r2.section("UPX1", "") and
		$upx
}
