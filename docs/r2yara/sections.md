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

##Examples

Some Yara rules examples we can generate:
 
Rule to looking for sections writables with “.text” name and size > 28KB
```sh 
import "r2" 
rule sections {
    Condition:
        for any i in ( 0..r2.number_of_sections ) : 
            (r2.sections[i].size > 28KB and     
             r2.sections[i].flags contains "-w-" and  
             r2.sections[i].name contains "text") }
``` 

We can to be interested in calculate the entropy by sections, and for example we can write a rule like this:
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