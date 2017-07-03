#Resources
There are two ways to look for specific exports in a binary.

##Functions
```
r2.resource(type, language)
```

Each parameter could be string or regex. In case any parameter is indiferent for you, can use empty string "", for instance:

We can want to look for binaries with an resource type "STRING" and in "JAPANESE":

```
r2.resource("STRING", "LANG_JAPANESE")
```

Or simply something in RUSSIAN:

```
r2.resource("", /RUSSIAN/)
```

##Array
The array called "resources" contains the following attributes:

- size
- paddr
- lang
- type

So with those you can construct simple or very complex rules, for instance:

```
rule resources {
	condition:
		for any i in ( 0..r2.number_of_resources ) : 
			(r2.resources[i].size > 2KB and
			 r2.resources[i].paddr > 1024 and
			 r2.resources[i].type == "ICON" and
			 r2.resources[i].lang contains "JAPANESE")
}
```