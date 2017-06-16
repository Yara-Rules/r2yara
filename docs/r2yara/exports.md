#Exports
There are two ways to look for specific exports in a binary.

##Functions
```
r2.export(name, type)
```

Each parameter could be string or regex. In case any parameter is indiferent for you, can use empty string "", for instance:

We can look for DLLs with an exported "function" called "ADVAPI32.dll_WriteEncryptedFileRaw", we can write any of the following conditions:

```
r2.export("ADVAPI32.dll_WmiQuerySingleInstanceW", "FUNC")

r2.export("ADVAPI32.dll_WmiQuerySingleInstanceW", /FUNC/)

r2.export(/WmiQuerySingleInstanceW/, "FUNC")

r2.export(/WmiQuerySingleInstance/, /func/i)
```
