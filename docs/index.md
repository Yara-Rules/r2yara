# Radare2 module for Yara
 
From [YaraRules Project](http://yararules.com/) we would like to introduce you a new Yara module that pretends to use information retrieved from radare2 (r2) to use with Yara.

To use this module it is important to know basic concepts about r2 and Yara. 
 
 
## Yara Modules
 
Modules are the way Yara provides for extending its features. They allow to define data structures and functions which can be used in your rules to express more complex conditions. There’re some modules (PE, ELF, Cuckoo, Math, etc.) officially distributed with Yara, but you can also write your own modules.
 
## Radare2
 
[Radare2](https://rada.re/r/) is a strong open-source reversing framework that allows -furtherother more functionalities- provides information over executables files that other tools doesn’t have in a direct way and it supports a lot of file format!: ELF, Java Class, Mach-O, COFF, Gameboy, Nintendo Switch bins, SNES roms, WASM, Compiled LUA, PCAP files, etc.
 
From YaraRules Project cooked this recipe:
 
                           Radare2 versatility + Power of Yara = r2.c (Radare2 module for Yara)
 
And we hope you find it interesting :)
 
## Installation
 
In the installation [section](https://github.com/Yara-Rules/r2yara/blob/master/docs/installation/installation.md)  you will found detailed instructions about the r2 installation and Yara configuration + installation.
 
There’re two ways to use r2.c:
 
* First way to use r2.c is passing Json report generated with Radare2. This is the quickly way to use with a lot amount samples.
```sh      
yara -x r2=report.json file.yar binary
```
* Second way is invoking automatically Radare2 from Yara. This method is recommendable to use manually. One of the powers of Yara, the speed, is considerably decreased using this method, but is very userful to quick tests.
```sh                               
yara file.yar binary
```
## What radare2 information can be used with the module?
 
We can write Yara rules with a lot of information from [rabin2](https://radare.gitbooks.io/radare2book/content/rabin2/intro.html) and [rahash2](https://radare.gitbooks.io/radare2book/content/rahash2/intro.html). 
 
Rabin2 is a powerful tool from radare2 framework to handle binary files, to get information on “imports”, sections, “symbols” (exported symbols), list archs, headers fields, binary info, libraries, etc. 
 
With Rahash2 we can calculate a checksum with a lot of different
Algorithms: md5, sha1, sha256, sha384, sha512, crc16, crc32, md4, xor, xorpair, parity, entropy, hamdist, pcprint, mod255, xxhash...etc.
 
## Examples
 
> ### Sections
 
With rabin2 we can obtain information about the sections of the binary and generate Yara rules with the next fields:
```sh (Name, flag, size, vsize, paddr) ``` 
 
Some Yara rules examples we can generate:
 
>> Rule to looking for sections writables with “.text” name and size > 28KB
```sh 
import "r2" 
rule sections {
    Condition:
        for any i in ( 0..r2.number_of_sections ) : 
            (r2.sections[i].size > 28KB and     
             r2.sections[i].flags contains "-w-" and  
             r2.sections[i].name contains "text") }
``` 
>>  We can to be interested in calculate the entropy by sections, and for example we can write a rule like this:
```sh 
import "r2"
import "math"
 
rule rule_sections_entropy_s 
{ 
 condition:  
for any i in ( 0..r2.number_of_sections ) : 
(r2.sections[i].name contains "note.ABI_tag" and 
math.entropy(r2.sections[i].paddr,      
r2.section_array[i].size) > 1.5) 
}
 
``` 
To end this part, remember each section has an standar name and for example you can search specific malware section names writing Yara rules. 
 
> ### Imported Symbols (Imports)

Rabin2 shows us imported symbols by an executable; useful information to understand, for instance, which external functions are being invoked. Yara Rule syntax is:
```sh 
r2.import(ordinal,bind,type,name)
```
Some Yara rules examples we can generate:
>> If a binary imports function URLDownloadToFile, we can intuit the sample connects to Internet to download something that it stores to disk:
```sh 
r2.import(-1,"","",URLDownloadToFile)
```
>> Function CreateProcessA said us the binary probably will create another process. it suggest when we run the program we must look the additional programs lauch:
```sh
r2.import(-1,"","",CreateProcessA)
```
To end this part, remember there're common Windows [functions](http://yararules.com/2017/04/06/yara-rules-strings-statistical-study/) found in malware and you can build Yara signatures to detect them.

> ### Exported Symbols (Exports)

In the same way as Imports, also there are exported functions or symbols to interact with other programs. Yara Rule syntax is:

```sh 
r2.symbol(name,type)
```
>> Example:
```sh 
r2.symbol(“__bss_start”,”OBJECT”)
```
> ### Bins: List archs

Rabin2 shows us information about archs, so we can use this information to write signatures. Yara Rule syntax is:

```sh 
r2.bin(arch, bits)
```
>> Examples:
```sh 
r2.bin(“x86”,64)
r2.bin(/86/,64)
r2.bin(/86/, -1)
r2.bin(“”,32)
```
> ### Header Fields

Yara Rule syntax:
```sh 
r2.field(name)
```
>> Example:
```sh 
for any i in (0..r2.number_of_fields) : 
(r2.fields[i].name == "phdr_6" 
and r2.fields[i].paddr > 300KB)
```
> ### Libraries

Yara Rule Syntax:
```sh 
r2.lib(library)
```
>> Example:
```sh 
r2.lib(“libselinux.so.1”)
```
> ### Binary info: File Properties Identification

Rabin2 shows us a lot of information with -I option: havecode, pic, canary, nx, crypto, va, intrp, bintype, class, lang, arch, bits, machine, os, minopsz, maxopsz, pcalign, subsys, endian, stripped, static, linenum, lsysm, relcos, binsz, rpath, compiled, dbg_file, guid.

We can write Yara Rules with this syntax:
```sh 
r2.info.havecode 
r2.info.pic  
r2.info.canary 
r2.info
...
```
>> Example: Search information about used protections in a binary checking the following parameters: Canary, PIC (Position Indepent Code), Nx (Non-executable stack):
```sh
import "r2"
rule protections { 
  condition: r2.info.canary == 1 and
  r2.info.pic == 1 and  
  r2.info.nx == 1 }
```
## More uses Cases
> ## Side effects of Packing

Packed and obfuscated code will often include at least the functions LoadLibrary and GetProcAddress, which are used to load and gain Access to additional functions. The section sizes can be useful in detecting packed executables. For example, if the Vsize is much larger than the size of raw data, you know that the section takes up more space in memory than it does on disk. This is often indicative of packed code, particularly if the .text section is larger in memory than on disk  and marked as code/executable (reference = "Practical Malware Analysis. BlackHat. Kris Kendall and Chad McMillan. Page 52")

To model a behaviour of packed/obfuscated code, for example, we can build rules like this (it's only an approach):
```sh
Import "r2"
rule difference_size_and_vsize {
meta: 
  description = "Rule to detect binaries with a big difference between section size and section vsize (after unpack). Also, it includes a big entropy and executable flags"  
  author = "@plutec_net, @mmorenog"  
  reference = "Practical Malware Analysis. BlackHat. Kris Kendall and Chad McMillan. Page 52" 

condition:  
  for any i in ( 0..r2.number_of_sections ) :  
  ((r2.section[i].vsize > r2.section[i].size*2) and 
  r2.section[i].flags contains "x" and  
  math.entropy(r2.section[i].paddr, r2.section[i].size) > 7) }

```
> ## Potential keylogger 

Detection of an hypothetical keylogger behaviour looking for “exports” symbols like: LowLevelKeyboardProc, LoveLevelMouseProc, functions like: SetWindowsHookEx, RegisterHotKey and string “Software\Microsoft\Windows\CurrentVersion\Run” usually found in malware.

```sh
import "r2" 
rule potential_keylogger {
meta: 
  description = "Rule to detect a potential keylogger" 
   author = "@plutec_net, @mmorenog" 
   reference "Practical Malware Analysis (book), page 18) 

strings:
  $autorun = "Software\Microsoft\Windows\CurrentVersion\Run" wide ascii 

condition: 
  r2.import(-1,"", "SetWindowsHookEx") and
  r2.import(-1,"", "RegisterHotKey") and
  r2.symbol("LowLevelKeyboardProc","") and 
  r2.symbol("LowLevelMouseProc","") and 
  $autorun }
```
> ## UPX Packer Example 

UPX packer is defined for 2 sections (UPX0 and UPX1), and it's so easy detect them with this module:

```sh
lab@lab:~/yara$ ./yara upx.yar upx.exe
[+] r2pipe child is 28499
UPX upx.exe

lab@lab:~/yara$ cat upx.yar
import "r2"
rule UPX{
  strings:
    $upx = "UPX"
  condition:
    r2.section("UPX0","") and
    r2.section("UPX1","") and
    $upx
}
```
> ## Resources & Languages

At this point we can look for certain resources. For instance, a resource “STRING” with “LANG_RUSSIAN” or “LANG_CHINESE” as language:
```sh
rule res_string_jap { 
  condition: 
    r2.resource("STRING", "LANG_RUSSIAN") or 
    r2.resource("STRING", "LANG_CHINESE") }
```
Or increase the complexity using size (>2KB): 
```sh
rule resource { 
  condition: 
    for any i in ( 0..r2.number_of_resources ) :  
    (r2.resources[i].size > 2KB and 
    r2.resources[i].type == "STRING" and 
    r2.resources[i].lang contains "RUSSIAN"
    or r2,resources[i].lang contains “CHINESE”) }
```


## Feedback and Contribution

Your feedback is highly appreciated!!! Please, If you’re interested in contributing with us, ask a question or sharing your Yara rules with us and Security Community, you can send a message to our Twitter account @YaraRules, or submit a pull request or issue on our Github Repository.

Our module is under the GNU-GPLv2 license. It’s open to any user or organization, as long as you use it under this license

## Thanks

Thanks for all the people that give us feedback during the development, specially:
- @Pancake and r2 core contributors 
- @newlog
- @plusvic

# Authors

- @plutec_net and @mmorenog
