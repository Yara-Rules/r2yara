rule simple
{
	strings:
		$elf = "ELF"
	condition:
		$elf
}