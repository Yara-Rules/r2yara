import "r2"

rule rule_exports_array
{
  condition:
    for any i in ( 0..r2.number_of_exports ) : 
      (r2.exports[i].name == "ADVAPI32.dll_WriteEncryptedFileRaw" and
      r2.exports[i].demname == "" and
      r2.exports[i].flagname == "sym.ADVAPI32.dll_WriteEncryptedFileRaw" and
      r2.exports[i].size == 0 and
      r2.exports[i].type == "FUNC" and
      r2.exports[i].vaddr > 1024 and
      r2.exports[i].paddr > 512)

    /*{"name":"ADVAPI32.dll_WriteEncryptedFileRaw","demname":"",
    "flagname":"sym.ADVAPI32.dll_WriteEncryptedFileRaw","size":0,
    "type":"FUNC","vaddr":2009733322,
    "paddr":265930}*/
}