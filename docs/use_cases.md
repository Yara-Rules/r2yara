# Use Cases
> ## Side effects of Packing

Packed and obfuscated code will often include at least the functions LoadLibrary and GetProcAddress, which are used to load and gain Access to additional functions. The section sizes can be useful in detecting packed executables. For example, if the Vsize is much larger than the size of raw data, you know that the section takes up more space in memory than it does on disk. This is often indicative of packed code, particularly if the .text section is larger in memory than on disk  and marked as code/executable (reference = "Practical Malware Analysis. BlackHat. Kris Kendall and Chad McMillan. Page 52")

To model a behaviour of packed/obfuscated code, for example, we can build rules like this (it's only an approach):
```
import "r2"
import "math"

rule difference_size_and_vsize {
  meta: 
    description = "Rule to detect binaries with a big difference between section size and section vsize (after unpack). Also, it includes a big entropy and executable flags"  
    author = "@plutec_net, @mmorenog"  
    reference = "Practical Malware Analysis. BlackHat. Kris Kendall and Chad McMillan. Page 52" 

  condition:  
    for any i in ( 0..r2.number_of_sections ) :  
      ((r2.section[i].vsize > r2.section[i].size*2) and 
      r2.section[i].flags contains "x" and  
      math.entropy(r2.section[i].paddr, r2.section[i].size) > 7) 

}

```
> ## Potential keylogger 

Detection of an hypothetical keylogger behaviour looking for “exports” symbols like: LowLevelKeyboardProc, LoveLevelMouseProc, functions like: SetWindowsHookEx, RegisterHotKey and string “Software\Microsoft\Windows\CurrentVersion\Run” usually found in malware.

```
import "r2" 

rule potential_keylogger {

  meta: 
    description = "Rule to detect a potential keylogger" 
    author = "@plutec_net, @mmorenog" 
    reference "Practical Malware Analysis (book), page 18"

  strings:
    $autorun = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide ascii 

  condition: 
    r2.import(-1,"", "SetWindowsHookEx") and
    r2.import(-1,"", "RegisterHotKey") and
    r2.symbol("LowLevelKeyboardProc","") and 
    r2.symbol("LowLevelMouseProc","") and 
    $autorun 

}
```
> ## UPX Packer Example 

UPX packer is defined for 2 sections (UPX0 and UPX1), and it's so easy detect them with this module:

```
import "r2"

rule UPX {

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
```
import "r2"

rule res_string_jap { 
  condition: 
    r2.resource("STRING", "LANG_RUSSIAN") or 
    r2.resource("STRING", "LANG_CHINESE") 
}
```

Or increase the complexity using size (>2KB): 
```
import "r2"

rule resource { 
  condition: 
    for any i in ( 0..r2.number_of_resources ) :  
      (r2.resources[i].size > 2KB and 
      r2.resources[i].type == "STRING" and 
      r2.resources[i].lang contains "RUSSIAN" or
      r2.resources[i].lang contains "CHINESE") 

}
```
