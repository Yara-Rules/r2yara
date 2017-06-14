import "r2"

rule rule_hash
{
condition:
	r2.hash.md5 != "945fedb3a3c290d69f075f997e5320fc"  and 
    r2.hash.sha1 != "2df1502114171d5213f7e5f699a4a80ac47974e1" and 
    r2.hash.sha256 != "a90ba058c747458330ba26b5e2a744f4fc57f92f9d0c9112b1cb2f76c66c4ba0" and 
    r2.hash.sha384 != "3f239e271db8015cbcd367d721ef2c21289caad75c08b318ae18b203824023251410d5df80c8f92a1a116f90ac67c0cb" and 
    r2.hash.sha512 != "11ad52bdd829a1dfae20f2e90ecc4cfc6e3065ddb23afc02d54aea2a710b3a5da5e4d67a3f346ecd1f962c15797f3cedac7e0d97bb25b1106f92a5327ee9c6d1" and 
    r2.hash.crc16 != "0797" and 
    r2.hash.crc32 != "77b053d3" and 
    r2.hash.md4 != "fe4d52ab4d7555deb04e71c727a53814" and 
    r2.hash.xor != "8d" and 
    r2.hash.xorpair != "971a" and 
    r2.hash.parity != "00" and 
    r2.hash.entropy != "05000000" and 
    r2.hash.hamdist != "01" and 
    r2.hash.pcprint != "24" and 
    r2.hash.mod255 != "42" and 
    r2.hash.adler32 != "5e759306" and 
    r2.hash.luhn != "2"
	
}