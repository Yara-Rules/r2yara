#Hash
Radare2 supports a lot of different hashes, more that yara supports by default, so, of course, we extract them to use inside Yara. Following the complete list of them:

- md5
- sha1
- sha256
- sha384
- sha512
- crc16
- crc32
- md4
- xor
- xorpair
- parity
- entropy
- hamdist
- pcprint
- mod255
- adler32
- luhn

The way to use them is easy too, simply by comparison:

```
rule rule_hash
{
condition:
	r2.hash.md5 != "945fedb3a3c290d69f075f997e5320fc" or
	r2.hash.crc32 contains "b053d"
}
```