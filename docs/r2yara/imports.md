#Imports
There is only one way to look imports in a binary, using functions

##Functions
```
r2.imports(integer, string, string, string)

r2.imports(ordinal, bind, type, name)
```

Each parameter could be string or regex (except the first one). In case any parameter is indiferent for you, can use empty string "", or -1 if you mean the ordinal, for instance:

We can look for binaries with import called "__ctype_toupper_loc", type "function" and Global and doesn't matter ordinal:
```
r2.imports(-1, "GLOBAL", "FUNC", "__ctype_toupper_loc")
```
##Examples

Some Yara rules examples we can generate:
If a binary imports function URLDownloadToFile, we can intuit the sample connects to Internet to download something that it stores to disk:
```sh 
r2.import(-1,"","",URLDownloadToFile)
```
Function CreateProcessA said us the binary probably will create another process. it suggest when we run the program we must look the additional programs lauch:
```sh
r2.import(-1,"","",CreateProcessA)
```
To end this part, remember there're common Windows [functions](http://yararules.com/2017/04/06/yara-rules-strings-statistical-study/) found in malware and you can build Yara signatures to detect them.