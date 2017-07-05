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
 
In the [installation section](https://github.com/Yara-Rules/r2yara/blob/master/docs/installation/installation.md) you will found detailed instructions about the r2 installation and Yara configuration + installation.
 
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

## Feedback and Contribution

Your feedback is highly appreciated!!! Please, If you’re interested in contributing with us, ask a question or sharing your Yara rules with us and Security Community, you can send a message to our Twitter account @YaraRules, or submit a pull request or issue on any of our Github Repository.

Our module is under the GNU-GPLv2 license. It’s open to any user or organization, as long as you use it under this license

## Thanks

Thanks for all the people that give us feedback during the development, specially:

- [@pancake](https://twitter.com/trufae) and other r2 contributors 
- [@newlog](https://twitter.com/Newlog_)
- [@plusvic](https://twitter.com/plusvic)

# Authors

- [@plutec_net](https://twitter.com/plutec_net)
- [@mmorenog](https://twitter.com/mmorenog)
