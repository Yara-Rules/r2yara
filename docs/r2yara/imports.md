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
