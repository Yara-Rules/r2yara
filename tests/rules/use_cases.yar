import "r2"
import "math"

rule difference_size_and_vsize {
	meta:
		description = "Rule to detect binaries with a big difference between section size and section vsize (after unpack). Also, it includes a big entropy and executable flags"
		author = "A.Sánchez <asanchez@plutec.net>, M.Moreno <mmoreno.maite@gmail.com>"
		reference = "Practical Malware Analysis. BlackHat. Kris Kendall and Chad McMillan. Page 52"

	condition:
		for any i in ( 0..r2.number_of_sections ) : 
			((r2.sections[i].vsize > r2.sections[i].size*2) and 
			 r2.sections[i].flags contains "x" and
			 math.entropy(r2.sections[i].paddr, r2.sections[i].size) > 1.5)
}