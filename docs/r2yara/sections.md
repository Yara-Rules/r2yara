#Sections
As usual, there are 2 ways to look for sections in a binary. The easy way is using functions:

##Functions
```
r2.section(name, flag)
```

Each parameter could be string or regex. In case any parameter is indiferent for you, can use empty string "", for instance:

We can search binaries with any section name called "dhscf" and doesn't matter flags:
```
r2.section("dhscf", "")
```

#Array
The second way is using array of sections with the following fields:

```
name: string
flags: string
size: integer
vsize: integer
paddr: integer
```

To explain the array, we want to look for apps with a section size > 28KB, "writeable and executable" and which name contains "test", so, we need to iterate over the array checking those values:

```
rule sections {
	condition:
		for any i in ( 0..r2.number_of_sections ) : 
			(r2.sections[i].size > 28KB and 
			 r2.sections[i].flags contains "r-x" and
			 r2.sections[i].name contains "text")
}
```