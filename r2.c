#include <jansson.h>
#include <string.h>
#include <inttypes.h>

#include <yara/re.h>
#include <yara/modules.h>

#include <r_socket.h>
#include <r_util.h>

#ifdef _WIN32
#define strcasecmp _stricmp
#endif

#define NUMBER_OF_HASHES 26

#define MODULE_NAME r2

/*
############################## IMPORTS #########################################  
 "imports": [
    {
      "ordinal": 1,
      "bind": "GLOBAL",
      "type": "FUNC",
      "name": "__ctype_toupper_loc",
      "plt": 4203248
    },
*/
/*
  Function to detect IMPORTS (with strings)
*/
define_function(import_isss) //ordinal, bind, type, name
{
  YR_OBJECT* imports_obj = get_object(module(), "imports");
  json_t* list = (json_t*) imports_obj->data;
  uint64_t result = 0, global_result = 0;
  size_t index;
  json_t* value;
  char *bind, *type, *name;
  int ordinal;
  char *arg_bind, *arg_type, *arg_name;
  int arg_ordinal;

  arg_ordinal = integer_argument(1);
  arg_bind = string_argument(2);
  arg_type = string_argument(3);
  arg_name = string_argument(4);


  if (arg_bind[0] == 0)   { arg_bind = NULL; global_result += 1; }
  if (arg_type[0] == 0)   { arg_type = NULL; global_result += 1; }
  if (arg_name[0] == 0)   { arg_name = NULL; global_result += 1; }
  if (arg_ordinal == -1)  { global_result += 1; }

  json_array_foreach(list, index, value)
  {
    result = global_result;
    bind = (char*)json_string_value(json_object_get(value, "bind"));
    type = (char*)json_string_value(json_object_get(value, "type"));
    name = (char*)json_string_value(json_object_get(value, "name"));
    ordinal = json_integer_value(json_object_get(value, "ordinal"));

    if (arg_ordinal == ordinal)                      { result += 1; }
    if (arg_bind && strcasecmp(arg_bind, bind) == 0) { result += 1; }
    if (arg_type && strcasecmp(arg_type, type) == 0) { result += 1; }
    if (arg_name && strcasecmp(arg_name, name) == 0) { result += 1; }
    if (result == 4) { break; }
  }
  
  if (result == 4) { return_integer(1); }
  return_integer(0);
}

/*
  Function to detect IMPORTS (name regex)
*/
define_function(import_issr) //ordinal, bind, type, name
{
  YR_OBJECT* imports_obj = get_object(module(), "imports");
  json_t* list = (json_t*) imports_obj->data;
  uint64_t result = 0, global_result = 0;
  size_t index;
  json_t* value;
  char *bind, *type, *name;
  int ordinal;
  char *arg_bind, *arg_type;
  RE* arg_name;
  int arg_ordinal;

  arg_ordinal = integer_argument(1);
  arg_bind = string_argument(2);
  arg_type = string_argument(3);
  arg_name = regexp_argument(4);


  if (arg_bind[0] == 0)   { arg_bind = NULL; global_result += 1; }
  if (arg_type[0] == 0)   { arg_type = NULL; global_result += 1; }
  if (arg_ordinal == -1)  { global_result += 1; }


  json_array_foreach(list, index, value)
  {
    result = global_result;

    bind = (char*)json_string_value(json_object_get(value, "bind"));
    type = (char*)json_string_value(json_object_get(value, "type"));
    name = (char*)json_string_value(json_object_get(value, "name"));
    ordinal = json_integer_value(json_object_get(value, "ordinal"));

    if (arg_ordinal == ordinal)                      { result += 1; }
    if (arg_bind && strcasecmp(arg_bind, bind) == 0) { result += 1; }
    if (arg_type && strcasecmp(arg_type, type) == 0) { result += 1; }
    if (yr_re_match(arg_name, name) > 0)             { result += 1; }
    if (result == 4) { break; }
  }
  
  if (result == 4) { return_integer(1); }
  return_integer(0);
}

/*
  Function to detect IMPORTS (type regex)
*/
define_function(import_isrs) //ordinal, bind, type, name
{
  YR_OBJECT* imports_obj = get_object(module(), "imports");
  json_t* list = (json_t*) imports_obj->data;
  uint64_t result = 0, global_result = 0;
  size_t index;
  json_t* value;
  char *bind, *type, *name;
  int ordinal;
  char *arg_bind, *arg_name;
  RE* arg_type;
  int arg_ordinal;

  arg_ordinal = integer_argument(1);
  arg_bind = string_argument(2);
  arg_type = regexp_argument(3);
  arg_name = string_argument(4);


  if (arg_bind[0] == 0)   { arg_bind = NULL; global_result += 1; }
  if (arg_name[0] == 0)   { arg_name = NULL; global_result += 1; }
  if (arg_ordinal == -1)  { global_result += 1; }

  json_array_foreach(list, index, value)
  {
    result = global_result;
    bind = (char*)json_string_value(json_object_get(value, "bind"));
    type = (char*)json_string_value(json_object_get(value, "type"));
    name = (char*)json_string_value(json_object_get(value, "name"));
    ordinal = json_integer_value(json_object_get(value, "ordinal"));

    if (arg_ordinal == ordinal)                      { result += 1; }
    if (arg_bind && strcasecmp(arg_bind, bind) == 0) { result += 1; }
    if (arg_name && strcasecmp(arg_name, name) == 0) { result += 1; }
    if (yr_re_match(arg_type, type) > 0) { result += 1; }
    if (result == 4) { break; }
  }
  
  if (result == 4) { return_integer(1); }
  return_integer(0);
}

define_function(import_isrr) //ordinal, bind, type, name
{
  YR_OBJECT* imports_obj = get_object(module(), "imports");
  json_t* list = (json_t*) imports_obj->data;
  uint64_t result = 0, global_result = 0;
  size_t index;
  json_t* value;
  char *bind, *type, *name;
  int ordinal;
  char *arg_bind;
  RE *arg_type, *arg_name;
  int arg_ordinal;

  arg_ordinal = integer_argument(1);
  arg_bind = string_argument(2);
  arg_type = regexp_argument(3);
  arg_name = regexp_argument(4);


  if (arg_bind[0] == 0)   { arg_bind = NULL; global_result += 1; }
  if (arg_ordinal == -1)  { global_result += 1; }

  json_array_foreach(list, index, value)
  {
    result = global_result;
    bind = (char*)json_string_value(json_object_get(value, "bind"));
    type = (char*)json_string_value(json_object_get(value, "type"));
    name = (char*)json_string_value(json_object_get(value, "name"));
    ordinal = json_integer_value(json_object_get(value, "ordinal"));

    if (arg_ordinal == ordinal)                      { result += 1; }
    if (arg_bind && strcasecmp(arg_bind, bind) == 0) { result += 1; }
    if (yr_re_match(arg_type, type) > 0) { result += 1; }
    if (yr_re_match(arg_name, name) > 0) { result += 1; }
    if (result == 4) { break; }
  }
  
  if (result == 4) { return_integer(1); }
  return_integer(0);
}
/*
  Function to detect IMPORTS (bind regex)
*/
define_function(import_irss) //ordinal, bind, type, name
{
  YR_OBJECT* imports_obj = get_object(module(), "imports");
  json_t* list = (json_t*) imports_obj->data;
  uint64_t result = 0, global_result = 0;
  size_t index;
  json_t* value;
  char *bind, *type, *name;
  int ordinal;
  char *arg_type, *arg_name;
  RE* arg_bind;  
  int arg_ordinal;

  arg_ordinal = integer_argument(1);
  arg_bind = regexp_argument(2);
  arg_type = string_argument(3);
  arg_name = string_argument(4);


  if (arg_type[0] == 0)   { arg_type = NULL; global_result += 1; }
  if (arg_name[0] == 0)   { arg_name = NULL; global_result += 1; }
  if (arg_ordinal == -1)  { global_result += 1; }

  json_array_foreach(list, index, value)
  {
    result = global_result;
    bind = (char*)json_string_value(json_object_get(value, "bind"));
    type = (char*)json_string_value(json_object_get(value, "type"));
    name = (char*)json_string_value(json_object_get(value, "name"));
    ordinal = json_integer_value(json_object_get(value, "ordinal"));

    if (arg_ordinal == ordinal)                      { result += 1; }
    if (arg_type && strcasecmp(arg_type, type) == 0) { result += 1; }
    if (arg_name && strcasecmp(arg_name, name) == 0) { result += 1; }
    if (yr_re_match(arg_bind, bind) > 0) { result += 1; }
    if (result == 4) { break; }
  }
  
  if (result == 4) { return_integer(1); }
  return_integer(0);
}



define_function(import_irsr) //ordinal, bind, type, name
{
  YR_OBJECT* imports_obj = get_object(module(), "imports");
  json_t* list = (json_t*) imports_obj->data;
  uint64_t result = 0, global_result = 0;
  size_t index;
  json_t* value;
  char *bind, *type, *name;
  int ordinal;
  char *arg_type;
  RE *arg_bind, *arg_name;
  int arg_ordinal;

  arg_ordinal = integer_argument(1);
  arg_bind = regexp_argument(2);
  arg_type = string_argument(3);
  arg_name = regexp_argument(4);


  if (arg_type[0] == 0)   { arg_type = NULL; global_result += 1; }
  if (arg_ordinal == -1)  { global_result += 1; }

  json_array_foreach(list, index, value)
  {
    result = global_result;
    bind = (char*)json_string_value(json_object_get(value, "bind"));
    type = (char*)json_string_value(json_object_get(value, "type"));
    name = (char*)json_string_value(json_object_get(value, "name"));
    ordinal = json_integer_value(json_object_get(value, "ordinal"));

    if (arg_ordinal == ordinal)                      { result += 1; }
    if (yr_re_match(arg_bind, bind) > 0) { result += 1; }
    if (arg_type && strcasecmp(arg_type, type) == 0) { result += 1; }
    if (yr_re_match(arg_name, name) > 0) { result += 1; }
    if (result == 4) { break; }
  }
  
  if (result == 4) { return_integer(1); }
  return_integer(0);
}

define_function(import_irrs) //ordinal, bind, type, name
{
  YR_OBJECT* imports_obj = get_object(module(), "imports");
  json_t* list = (json_t*) imports_obj->data;
  uint64_t result = 0, global_result = 0;
  size_t index;
  json_t* value;
  char *bind, *type, *name;
  int ordinal;
  char *arg_name;
  RE *arg_bind, *arg_type;
  int arg_ordinal;

  arg_ordinal = integer_argument(1);
  arg_bind = regexp_argument(2);
  arg_type = regexp_argument(3);
  arg_name = string_argument(4);


  if (arg_name[0] == 0)   { arg_name = NULL; global_result += 1; }
  if (arg_ordinal == -1)  { global_result += 1; }

  json_array_foreach(list, index, value)
  {
    result = global_result;
    bind = (char*)json_string_value(json_object_get(value, "bind"));
    type = (char*)json_string_value(json_object_get(value, "type"));
    name = (char*)json_string_value(json_object_get(value, "name"));
    ordinal = json_integer_value(json_object_get(value, "ordinal"));

    if (arg_ordinal == ordinal)                      { result += 1; }
    if (yr_re_match(arg_bind, bind) > 0) { result += 1; }
    if (yr_re_match(arg_type, type) > 0) { result += 1; }
    if (arg_name && strcasecmp(arg_name, name) == 0) { result += 1; }
    if (result == 4) { break; }
  }
  
  if (result == 4) { return_integer(1); }
  return_integer(0);
}

define_function(import_irrr) //ordinal, bind, type, name
{
  YR_OBJECT* imports_obj = get_object(module(), "imports");
  json_t* list = (json_t*) imports_obj->data;
  uint64_t result = 0;
  size_t index;
  json_t* value;
  char *bind, *type, *name;
  int ordinal;
  RE *arg_bind, *arg_type, *arg_name;
  int arg_ordinal;

  arg_ordinal = integer_argument(1);
  arg_bind = regexp_argument(2);
  arg_type = regexp_argument(3);
  arg_name = regexp_argument(4);


  json_array_foreach(list, index, value)
  {
    result = 0;
    bind = (char*)json_string_value(json_object_get(value, "bind"));
    type = (char*)json_string_value(json_object_get(value, "type"));
    name = (char*)json_string_value(json_object_get(value, "name"));
    ordinal = json_integer_value(json_object_get(value, "ordinal"));

    if (arg_ordinal == -1 || arg_ordinal == ordinal) { result += 1; }
    if (yr_re_match(arg_bind, bind) > 0)             { result += 1; }
    if (yr_re_match(arg_type, type) > 0)             { result += 1; }
    if (yr_re_match(arg_name, name) > 0)             { result += 1; }
    if (result == 4) { break; }
  }
  
  if (result == 4) { return_integer(1); }
  return_integer(0);
}
/*
############################# SECTIONS #########################################  
"sections": [
    {
      "name": "",
      "size": 0,
      "vsize": 0,
      "flags": "-----",
      "paddr": 0,
      "vaddr": 0
    },
*/
/*
  Function to detect SECTIONS (with strings)
*/
define_function(section_ss) // name,flags

{
  
  YR_OBJECT* sections_obj = get_object(module(), "sections");
  json_t* list = (json_t*) sections_obj->data;
  uint64_t result = 0, global_result = 0;
  size_t index;
  json_t* value;
  char *name, *flags;
  char *arg_name, *arg_flags;  

  arg_name = string_argument(1);
  arg_flags = string_argument(2);


  if (arg_name[0] == 0)       { arg_name = NULL; global_result += 1; }
  if (arg_flags[0] == 0)      { arg_flags = NULL; global_result += 1; }

  json_array_foreach(list, index, value)
  {
    result = global_result;
    
    name = (char*)json_string_value(json_object_get(value, "name"));
    flags = (char*)json_string_value(json_object_get(value, "flags"));

    if (arg_name && strcasecmp(arg_name, name) == 0) { result += 1; }
    if (arg_flags && strcasecmp(arg_flags, flags) == 0) { result += 1; }

    if (result == 2) { break; }
  }
  
  if (result == 2) { return_integer(1); }
  return_integer(0);
}

/*
  Function to detect SECTIONS (flags regex)
*/
define_function(section_sr) //name,flags
{
  
  YR_OBJECT* sections_obj = get_object(module(), "sections");
  json_t* list = (json_t*) sections_obj->data;
  uint64_t result = 0, global_result = 0;
  size_t index;
  json_t* value;
  char *name, *flags;
  char *arg_name;
  RE* arg_flags;  

  arg_name = string_argument(1);
  arg_flags = regexp_argument(2);
  
  if (arg_name[0] == 0) { arg_name = NULL; global_result += 1; }

  json_array_foreach(list, index, value)
  {
    result = global_result;
    name = (char*)json_string_value(json_object_get(value, "name"));
    flags = (char*)json_string_value(json_object_get(value, "flags"));

    if (arg_name && strcasecmp(arg_name, name) == 0) { result += 1; }
    if (yr_re_match(arg_flags, flags) > 0)           { result += 1; }
    if (result == 2) { break; }
  }
  
  if (result == 2) { return_integer(1); }
  return_integer(0);
}

/*
  Function to detect SECTIONS (name regex)
*/
define_function(section_rs) //name,flags
{
  
  YR_OBJECT* sections_obj = get_object(module(), "sections");
  json_t* list = (json_t*) sections_obj->data;
  uint64_t result = 0, global_result = 0;
  size_t index;
  json_t* value;
  char *name, *flags;
  char *arg_flags;
  RE* arg_name;  

  arg_name = regexp_argument(1);
  arg_flags = string_argument(2);

  if (arg_flags[0] == 0) { arg_flags = NULL; global_result += 1; }

  json_array_foreach(list, index, value)
  {
    result = global_result;
    name = (char*)json_string_value(json_object_get(value, "name"));
    flags = (char*)json_string_value(json_object_get(value, "flags"));

    if (yr_re_match(arg_name, name) > 0)                { result += 1; }
    if (arg_flags && strcasecmp(arg_flags, flags) == 0) { result += 1; }
    if (result == 2) { break; }
  }
  
  if (result == 2) { return_integer(1); }
  return_integer(0);
}

/*
  Function to detect SECTIONS (name,flags regex)
*/
define_function(section_rr) // name, flags
{
  
  YR_OBJECT* sections_obj = get_object(module(), "sections");
  json_t* list = (json_t*) sections_obj->data;
  uint64_t result = 0;
  size_t index;
  json_t* value;
  char *name, *flags;
  RE *arg_name, *arg_flags;

  arg_name = regexp_argument(1);
  arg_flags = regexp_argument(2);

  json_array_foreach(list, index, value)
  {
    result = 0;
    
    name = (char*)json_string_value(json_object_get(value, "name"));
    flags = (char*)json_string_value(json_object_get(value, "flags"));
  
    if (yr_re_match(arg_name, name) > 0)   { result += 1; }
    if (yr_re_match(arg_flags, flags) > 0) { result += 1; }
    
    if (result == 2) { break; }
  }
  
  if (result == 2) { return_integer(1); }
  return_integer(0);
}



/****************** RESOURCE **************************/

/*
  Functions to detect RESOURCES
*/
define_function(resource_ss) // type, lang

{
  
  YR_OBJECT* sections_obj = get_object(module(), "resources");
  json_t* list = (json_t*) sections_obj->data;
  uint64_t result = 0, global_result = 0;
  size_t index;
  json_t* value;
  char *type, *lang;
  char *arg_type, *arg_lang;  

  arg_type = string_argument(1);
  arg_lang = string_argument(2);


  if (arg_type[0] == 0)       { arg_type = NULL; global_result += 1; }
  if (arg_lang[0] == 0)       { arg_lang = NULL; global_result += 1; }

  json_array_foreach(list, index, value)
  {
    result = global_result;
    
    type = (char*)json_string_value(json_object_get(value, "type"));
    lang = (char*)json_string_value(json_object_get(value, "lang"));

    if (arg_type && strcasecmp(arg_type, type) == 0) { result += 1; }
    if (arg_lang && strcasecmp(arg_lang, lang) == 0) { result += 1; }

    if (result == 2) { break; }
  }
  
  if (result == 2) { return_integer(1); }
  return_integer(0);
}

define_function(resource_sr) //type, lang
{
  
  YR_OBJECT* sections_obj = get_object(module(), "resources");
  json_t* list = (json_t*) sections_obj->data;
  uint64_t result = 0, global_result = 0;
  size_t index;
  json_t* value;
  char *type, *lang;
  char *arg_type;
  RE* arg_lang;  

  arg_type = string_argument(1);
  arg_lang = regexp_argument(2);
  
  if (arg_type[0] == 0) { arg_type = NULL; global_result += 1; }

  json_array_foreach(list, index, value)
  {
    result = global_result;
    type = (char*)json_string_value(json_object_get(value, "type"));
    lang = (char*)json_string_value(json_object_get(value, "lang"));

    if (arg_type && strcasecmp(arg_type, type) == 0) { result += 1; }
    if (yr_re_match(arg_lang, lang) > 0)             { result += 1; }
    if (result == 2) { break; }
  }
  
  if (result == 2) { return_integer(1); }
  return_integer(0);
}

define_function(resource_rs) //type, lang
{
  
  YR_OBJECT* sections_obj = get_object(module(), "resources");
  json_t* list = (json_t*) sections_obj->data;
  uint64_t result = 0, global_result = 0;
  size_t index;
  json_t* value;
  char *type, *lang;
  char *arg_lang;
  RE* arg_type;  

  arg_type = regexp_argument(1);
  arg_lang = string_argument(2);

  if (arg_lang[0] == 0) { arg_lang = NULL; global_result += 1; }

  json_array_foreach(list, index, value)
  {
    result = global_result;
    type = (char*)json_string_value(json_object_get(value, "type"));
    lang = (char*)json_string_value(json_object_get(value, "lang"));

    if (yr_re_match(arg_type, type) > 0)                { result += 1; }
    if (arg_lang && strcasecmp(arg_lang, lang) == 0)    { result += 1; }
    if (result == 2) { break; }
  }
  
  if (result == 2) { return_integer(1); }
  return_integer(0);
}

define_function(resource_rr) // type, lang
{
  
  YR_OBJECT* sections_obj = get_object(module(), "resources");
  json_t* list = (json_t*) sections_obj->data;
  uint64_t result = 0;
  size_t index;
  json_t* value;
  char *type, *lang;
  RE *arg_type, *arg_lang;

  arg_type = regexp_argument(1);
  arg_lang = regexp_argument(2);

  json_array_foreach(list, index, value)
  {
    result = 0;
    
    type = (char*)json_string_value(json_object_get(value, "type"));
    lang = (char*)json_string_value(json_object_get(value, "lang"));
  
    if (yr_re_match(arg_type, type) > 0)   { result += 1; }
    if (yr_re_match(arg_lang, lang) > 0)   { result += 1; }
    
    if (result == 2) { break; }
  }
  
  if (result == 2) { return_integer(1); }
  return_integer(0);
}

/********************************* LIBS ***************************************/
/*
  Function to detect LIBS
*/
define_function(lib_s)
{
  
  YR_OBJECT* obj = get_object(module(), "lib");
  uint64_t result = 0;
  size_t index;
  json_t* value;

  json_array_foreach(obj->data, index, value)
  {
    if (strcasecmp(string_argument(1), (char*)json_string_value(value)) == 0) { 
      result = 1;
      break; 
    }
  }
  
  return_integer(result);
}

define_function(lib_r)
{
  
  YR_OBJECT* obj = get_object(module(), "lib");
  uint64_t result = 0;
  size_t index;
  json_t* value;

  json_array_foreach(obj->data, index, value)
  {
    if (yr_re_match(regexp_argument(1), (char*)json_string_value(value)) > 0) { 
      result = 1;
      break; 
    }
  }
  
  return_integer(result);
}


/*
##################################################################################### SYMBOLS ###############################################################################  
"symbols": [
    {
      "name": "__bss_start",
      "demname": "",
      "flagname": "obj.__bss_start",
      "size": 8,
      "type": "OBJECT",
      "vaddr": 6415872,
      "paddr": 124416
    },
*/
/*
  Function to detect SYMBOLS (with strings)
*/
define_function(export_ss) // name, type
{
  YR_OBJECT* export_obj = get_object(module(), "exports");
  json_t* list = (json_t*) export_obj->data;
  uint64_t result = 0, global_result = 0;
  size_t index;
  json_t* value;
  char *name, *type;
  char *arg_name, *arg_type;  

  arg_name = string_argument(1);
  arg_type = string_argument(2);


  if (arg_name[0] == 0) { arg_name = NULL; global_result += 1; }
  if (arg_type[0] == 0) { arg_type = NULL; global_result += 1; }

  json_array_foreach(list, index, value)
  {
    result = global_result;
    
    name = (char*)json_string_value(json_object_get(value, "name"));
    type = (char*)json_string_value(json_object_get(value, "type"));

    if (arg_name && strcasecmp(arg_name, name) == 0) { result += 1; }
    if (arg_type && strcasecmp(arg_type, type) == 0) { result += 1; }

    if (result == 2) { break; }
  }
  
  if (result == 2) { return_integer(1); }
  return_integer(0);
}

/*
  Function to detect SYMBOLS (name regex)
*/
define_function(export_sr) // name, type
{
  
  YR_OBJECT* export_obj = get_object(module(), "exports");
  json_t* list = (json_t*) export_obj->data;
  uint64_t result = 0, global_result = 0;
  size_t index;
  json_t* value;
  char *name, *type;
  char *arg_name;
  RE* arg_type;  

  arg_name  = string_argument(1);
  arg_type = regexp_argument(2);

  if (arg_name[0] == 0)     { arg_name = NULL; global_result += 1; }
  
  json_array_foreach(list, index, value)
  {
    result = global_result;
    
    name = (char*)json_string_value(json_object_get(value, "name"));
    type = (char*)json_string_value(json_object_get(value, "type"));

  
    if (arg_name && strcasecmp(arg_name, name) == 0) { result += 1; }
    if (yr_re_match(arg_type, type) > 0) { result += 1; }
    if (result == 2) { break; }
  }
  
  if (result == 2) { return_integer(1); }
  return_integer(0);
}

/*
  Function to detect SYMBOLS (demname regex)
*/
define_function(export_rs) // name,type
{
  
  YR_OBJECT* export_obj = get_object(module(), "exports");
  json_t* list = (json_t*) export_obj->data;
  uint64_t result = 0, global_result = 0;
  size_t index;
  json_t* value;
  char *name, *type;
  char *arg_type;
  RE* arg_name;  

  arg_name = regexp_argument(1);
  arg_type  = string_argument(2);

  if (arg_type[0] == 0)     { arg_type = NULL; global_result += 1; }
  
  json_array_foreach(list, index, value)
  {
    result = global_result;
    
    name = (char*)json_string_value(json_object_get(value, "name"));
    type = (char*)json_string_value(json_object_get(value, "type"));

  
    if (yr_re_match(arg_name, name) > 0) { result += 1; }
    if (arg_type && strcasecmp(arg_type, type) == 0) { result += 1; }
    if (result == 2) { break; }
  }
  
  if (result == 2) { return_integer(1); }
  return_integer(0);
}


/*
  Function to detect SYMBOLS (flagname regex)
*/
define_function(export_rr) // name,demname,flagname,type
{
  
  YR_OBJECT* export_obj = get_object(module(), "exports");
  json_t* list = (json_t*) export_obj->data;
  uint64_t result = 0;
  size_t index;
  json_t* value;
  char *name, *type;
  RE *arg_name, *arg_type;  

  arg_name = regexp_argument(1);
  arg_type = regexp_argument(2);

  json_array_foreach(list, index, value)
  {
    result = 0;
    
    name = (char*)json_string_value(json_object_get(value, "name"));
    type = (char*)json_string_value(json_object_get(value, "type"));


    if (yr_re_match(arg_name, name) > 0) { result += 1; }
    if (yr_re_match(arg_type, type) > 0) { result += 1; }
    if (result == 2) { break; }
  }
  
  if (result == 2) { return_integer(1); }
  return_integer(0);
}

/*
##################################################################################### BINS ###############################################################################  
"bins": [
    {
      "arch": "x86",
      "bits": 64,
      "offset": 0
    }
*/
/*
  Function to detect BINS (with strings)
*/
  /*
define_function(bin_si) // arch, bits 
//{"bins":[{"arch":"x86","bits":64,"offset":0}]}
//rabin2 -A List archs

{
  
  YR_OBJECT* bin_obj = get_object(module(), "bin");
  json_t* list = (json_t*) bin_obj->data;
  uint64_t result = 0, global_result = 0;
  size_t index;
  json_t* value;
  char *arch;
  char *arg_arch;  
  int arg_bits, bits;

  arg_arch = string_argument(1);
  arg_bits = integer_argument(2);
    
  if (arg_arch[0] == 0) { arg_arch = NULL; global_result += 1; }

  json_array_foreach(list, index, value)
  {
    result = global_result;
    arch = (char*)json_string_value(json_object_get(value, "arch"));
    bits = json_integer_value(json_object_get(value, "bits"));

    if (arg_bits == -1 || arg_bits == bits)        { result += 1; }
    if (arg_arch && strcasecmp(arg_arch, arch) == 0) { result += 1; }
    if (result == 2) { break; }
  }
  
  if (result == 2) { return_integer(1); }
  return_integer(0);
}*/
/*
  Function to detect BINS (arch regex)
*/
/*
define_function(bin_ri) // arch, bits
{
  YR_OBJECT* bin_obj = get_object(module(), "bin");
  json_t* list = (json_t*) bin_obj->data;
  uint64_t result = 0, global_result = 0;
  size_t index;
  json_t* value;
  char *arch;
  RE* arg_arch;
  int arg_bits, bits;

  arg_arch = regexp_argument(1);
  arg_bits = integer_argument(2);

  json_array_foreach(list, index, value)
  {
    result = global_result;
    arch = (char*)json_string_value(json_object_get(value, "arch"));
    bits = json_integer_value(json_object_get(value, "bits"));
    
    if (arg_bits == -1 || arg_bits == bits)        { result += 1; }
    if (yr_re_match(arg_arch, arch) > 0) { result += 1; }
    if (result == 2) { break; }
  }
  
  if (result == 2) { return_integer(1); }
  return_integer(0);
}
*/
/*
##################### HASH ##################################################  
 [{"name":"md5","hash":"c4e5f7fcbcef75924b2abde2b2e75f3f"},
 Options rahash2 -a all 
 md5, sha1, sha256, sha384, sha512, crc16, crc32, md4, xor, xorpair, parity, entropy, hamdist, pcprint, mod255, xxhash, adler32,
*/
/*
  Function to detect HASH (with strings)
*/
define_function(hash_ss) //name, hash
{
  
  YR_OBJECT* hash_obj = get_object(module(), "hash");
  json_t* list = (json_t*) hash_obj->data;
  uint64_t result = 0, global_result = 0;
  size_t index;
  json_t* value;
  char *name , *hash;
  char *arg_name, *arg_hash;  

  arg_name = string_argument(1);
  arg_hash = string_argument(2);

  if (arg_name[0] == 0) { arg_name = NULL; global_result += 1; }
  if (arg_hash[0] == 0) { arg_hash = NULL; global_result += 1; }

  json_array_foreach(list, index, value)
  {
    result = global_result;
    name = (char*)json_string_value(json_object_get(value, "name"));
    hash = (char*)json_string_value(json_object_get(value, "hash"));


    if (arg_name && strcasecmp(arg_name, name) == 0) { result += 1; }
    if (arg_hash && strcasecmp(arg_hash, hash) == 0) { result += 1; }

    if (result == 2) { break; }
  }
  
  if (result == 2) { return_integer(1); }
  return_integer(0);
}

//Symbols:
//rabin2 -sj /bin/ls

//Strings
//rabin2 -zj /bin/ls

//bins
//rabin2 -Aj /bin/ls

//fields
//rabin2 -Hj /bin/ls

//info
//rabin2 -Ij /bin/ls



/*
  Declarations
*/
begin_declarations;
 
  //rabin2 -ij /bin/ls    
  declare_function("imports", "isss", "i", import_isss);
  declare_function("imports", "issr", "i", import_issr);
  declare_function("imports", "isrs", "i", import_isrs);
  declare_function("imports", "isrr", "i", import_isrr);
  declare_function("imports", "irss", "i", import_irss);
  declare_function("imports", "irsr", "i", import_irsr);
  declare_function("imports", "irrs", "i", import_irrs);
  declare_function("imports", "irrr", "i", import_irrr);
  //TODO import array

  //rabin2 -lj /bin/ls
  declare_function("lib", "s", "i", lib_s); 
  declare_function("lib", "r", "i", lib_r);

  //rabin2 -Sj /bin/ls
  declare_function("section", "ss", "i", section_ss);
  declare_function("section", "sr", "i", section_sr);
  declare_function("section", "rs", "i", section_rs);
  declare_function("section", "rr", "i", section_rr);
  
  begin_struct_array("sections");
    declare_string("name");
    declare_string("flags");
    declare_integer("size");
    declare_integer("vsize");
    declare_integer("paddr");
  end_struct_array("sections");
  declare_integer("number_of_sections");

  /* Resources (type, lang) */
  declare_function("resource", "ss", "i", resource_ss);
  declare_function("resource", "sr", "i", resource_sr);
  declare_function("resource", "rs", "i", resource_rs);
  declare_function("resource", "rr", "i", resource_rr);

  begin_struct_array("resources");
    declare_integer("size");
    declare_integer("paddr");
    declare_string("lang");
    declare_string("type");
  end_struct_array("resources");
  declare_integer("number_of_resources");

  // Symbol
  declare_function("export","ss","i", export_ss); 
  declare_function("export","sr","i", export_sr); 
  declare_function("export","rs","i", export_rs); 
  declare_function("export","rr","i", export_rr); 
  
  begin_struct_array("exports");
    declare_string("demname");
    declare_string("name");
    declare_string("flagname");
    declare_integer("paddr");
    declare_string("type");
    declare_integer("vaddr");
    declare_integer("size");
  end_struct_array("exports");
  declare_integer("number_of_exports");

  /*
  begin_struct_array("fields");
    declare_string("name");
    declare_integer("paddr");
    declare_integer("vaddr");
  end_struct_array("fields");
  declare_integer("number_of_fields");
  */

  begin_struct("hash");
    declare_string("md5");
    declare_string("sha1");
    declare_string("sha256");
    declare_string("sha384");
    declare_string("sha512");
    declare_string("crc16");
    declare_string("crc24");
    declare_string("crc32");
    declare_string("crc32c");
    declare_string("crc32ecma267");
    declare_string("md4");
    declare_string("xor");
    declare_string("xorpair");
    declare_string("parity");
    declare_string("entropy");
    declare_string("hamdist");
    declare_string("pcprint");
    declare_string("mod255");
    declare_string("xxhash");
    declare_string("adler32");
    declare_string("luhn");
    declare_string("crc8smbus");
    declare_string("crc15can");
    declare_string("crc16hdlc");
    declare_string("crc16usb");
    declare_string("crc16citt");
  end_struct("hash");

  begin_struct("info");
    declare_integer("havecode"); //"havecode": true,
    declare_integer("pic"); //"pic": false,
    declare_integer("canary"); //"canary": true,
    declare_integer("nx"); //"nx": true,
    declare_integer("crypto"); //"crypto": false,
    declare_integer("va"); //"va": true,
    declare_string("intrp"); //"intrp": "/lib64/ld-linux-x86-64.so.2",
    declare_string("bintype"); //"bintype": "elf",
    declare_string("class"); //"class": "ELF64",
    declare_string("lang"); //"lang": "c",
    declare_string("arch"); //"arch": "x86",
    declare_integer("bits"); //"bits": 64,
    declare_string("machine"); //"machine": "AMD x86-64 architecture",
    declare_string("os"); //"os": "linux",
    declare_integer("minopsz"); //"minopsz": 1,
    declare_integer("maxopsz"); //"maxopsz": 16,
    declare_integer("pcalign"); //"pcalign": 0,
    declare_string("subsys"); //"subsys": "linux",
    declare_string("endian"); //"endian": "little",
    declare_integer("stripped"); //"stripped": true,
    declare_integer("static"); //"static": false,
    declare_integer("linenum"); //"linenum": false,
    declare_integer("lsyms"); //"lsyms": false,
    declare_integer("relocs"); //"relocs": false,
    declare_integer("binsz"); //"binsz": 124726,
    declare_string("rpath"); //"rpath": "NONE",
    declare_string("compiled"); //"compiled": "",
    declare_string("dbg_file"); //"dbg_file": "",
    declare_string("guid"); //"guid": ""
  end_struct("info");
  
end_declarations;
  
  
/*
  Initialize module
*/
int module_initialize(
    YR_MODULE* module)
{
  return ERROR_SUCCESS;
}
/*
  Finalize module
*/
int module_finalize(
    YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

/* Functions to interact with R2 */

char* r2cmd(R2Pipe *r2, const char *cmd) {
  char *msg = r2p_cmd (r2, cmd);
  if (msg) {
    return msg;
  }
  return NULL;
}

#define BLOCK_SIZE_R2 1024

void r2wx(R2Pipe *r2, const uint8_t *bytes, const int length) {
  char *buf_ptr;
  int i;
  //int number_of_blocks = (length/BLOCK_SIZE_R2)+1;
  //int written_bytes = 0;
  int to_write_len = 0;
  int offset = 0;
  //printf("Number of blocks %d\n", number_of_blocks);
  for (i=0;i<(length/BLOCK_SIZE_R2)+1;++i) {
    //TODO do this with min
    if (length - offset < BLOCK_SIZE_R2) {
      to_write_len = length - offset;
    } else {
      to_write_len = BLOCK_SIZE_R2;
    }
    //printf("TOWRITE LEN: %d\n", to_write_len);
    buf_ptr = (char*)malloc(sizeof(char)*((to_write_len*2)+5));
    sprintf(buf_ptr, "wxs %s", r_hex_bin2strdup(bytes+offset, to_write_len));
    //printf("%s\n", buf_ptr);
    offset += to_write_len;
    char *msg = r2p_cmd (r2, buf_ptr);
    if (msg) {
      //printf("[r2wx]: %s\n", msg);
      free (msg);
    }
    free(buf_ptr);
  }
}

/*
  PrepaRE* r2pipe
*/
 /* 
void prepare_r2(R2Pipe *r2, YR_MEMORY_BLOCK* block) {
  r2wx(r2, block->fetch_data, block->size);
}
*/

/*
  Module load
*/
int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
  /* Definitions */
  YR_OBJECT* imports_obj = NULL;
  YR_OBJECT* sections_obj = NULL;
  YR_OBJECT* resources_obj = NULL;
  YR_OBJECT* lib_obj = NULL;
  YR_OBJECT* export_obj = NULL;
  //YR_OBJECT* bin_obj = NULL;
  YR_OBJECT* info_obj = NULL;
  YR_OBJECT* hash_obj = NULL;
  R2Pipe *r2 = NULL;
  char hash_names[NUMBER_OF_HASHES][16] = {"md5", "sha1", "sha256", "sha384", "sha512",
        "crc16", "crc24", "crc32", "crc32c", "crc32ecma267", "md4", "xor", "xorpair", 
        "parity", "entropy", "hamdist", "pcprint", "mod255", "xxhash", "adler32", 
        "luhn", "crc8smbus", "crc15can", "crc16hdlc", "crc16usb", "crc16citt"};

/*
    "md5", "sha1", "sha256", "sha384",
      "sha512", "crc16", "crc32", "md4", "xor", "xorpair", "parity", "entropy", "hamdist",
      "pcprint", "mod255", "xxhash", "adler32", "luhn", "crc8smbus", "crc15can", "crc16hdlc",
      "crc16usb", "crc16citt", "crc24", "crc32c", "crc32ecma267"};*/

  json_error_t json_error;
  json_t* json = NULL;
  json_t* info = NULL;
  json_t* hash = NULL;

  YR_MEMORY_BLOCK* block = NULL;
  YR_MEMORY_BLOCK_ITERATOR* iterator = NULL;

  json_t* value;
  size_t index;
  size_t i=0;
  char *msg;

  //YR_SCAN_CONTEXT* context = scan_context();


  /* End definitions */

  /* Assign each object to their variables */
  
  imports_obj = get_object(module_object, "imports");
  sections_obj = get_object(module_object, "sections");
  resources_obj = get_object(module_object, "resources");
  export_obj = get_object(module_object, "exports");
  //bin_obj = get_object(module_object, "bin");
  lib_obj = get_object(module_object, "lib");
  info_obj = get_object(module_object, "info");
  hash_obj = get_object(module_object,"hash");


  if (module_data == NULL) {
    block = first_memory_block(context);
    iterator = context->iterator;

  } else {
    json = json_loadb(
        (const char*) module_data,
        module_data_size,
        0,
        &json_error);
    if (!json) {
      printf("ERROR: %s\n", json_error.text);
    }
    //printf("%s", (const char*) module_data);
    if (json == NULL)
      return ERROR_INVALID_FILE;
  }

  if (json == NULL && module_data == NULL) {
    msg = (char*)malloc(sizeof(char)*256);
    if (msg) {
      //sprintf(msg, "r2 -q0 malloc://%"PRIu64, context->file_size);
      sprintf(msg, "r2 -q0 -e bin.strings=false malloc://%"PRIu64, context->file_size);
      //printf(msg);
      //printf('\n');
      r2 = r2p_open(msg);
      free(msg); 
    } 

    if (r2) {
      foreach_memory_block(iterator, block)
      {
        uint8_t* block_data = block->fetch_data(block);
        r2wx(r2, block_data, block->size);
      }

      //r2cmd(r2, "s 0");
      //r2cmd(r2, "wtf!");
      msg = r2cmd (r2, "oa 0"); //Load binary information
      if (msg) { free(msg); }

      //Get imports
      //iij -> imports
      msg = r2cmd(r2, "iij");
      if (msg) {
        //printf("%s\n", msg);
        imports_obj->data = json_loadb(
          (const char*) msg, strlen(msg), 0, &json_error);
      }

      //Get resources
      //iRj -> resources
      msg = r2cmd(r2, "iRj");
      if (msg) {
        //printf("%s\n", msg);
        resources_obj->data = json_loadb(
          (const char*) msg, strlen(msg), 0, &json_error);
      }

      //Get sections
      //Sj -> Sections
      msg = r2cmd(r2, "iSj");
      if (msg) {
        sections_obj->data = json_loadb(
          (const char*) msg, strlen(msg), 0, &json_error);
      }
      
      //Get exports
      //isj -> (exports)
      msg = r2cmd(r2, "iEj");
      if (msg) {
        //printf("%s\n", msg);
        export_obj->data = json_loadb(
          (const char*) msg, strlen(msg), 0, &json_error);
      }


      //Get bin info
      msg = r2cmd(r2, "iIj");
      if (msg) {
        //printf("LEN %d: %s\n", strlen(msg), msg);
        info = json_loadb(
          (const char*) msg, strlen(msg), 0, &json_error);
      }
      //iAj -> arch, con rabin2 es -Aj TODO
      //iHj -> List headers,con rabin2 es -Hj
      //iIj -> Binary info
      //ilj -> linked libraries

      //Get linked libraries
      msg = r2cmd(r2, "ilj");
      if (msg) {
        //printf("LEN %d: %s\n", strlen(msg), msg);
        lib_obj->data = json_loadb(
          (const char*) msg, strlen(msg), 0, &json_error);
      }
      
      
      /* Hash */
      hash = json_array();
      json_t* this_hash;
      char* hash_value;
      for (i=0;i<NUMBER_OF_HASHES;i++) {
        this_hash = json_object();
        sprintf(msg, "ph %s $s @ 0", hash_names[i]);
        hash_value = r2cmd(r2, msg);
        hash_value[strlen(hash_value)-1] = '\0';
        json_object_set_new( this_hash, "name", json_string(hash_names[i]) );
        json_object_set_new( this_hash, "hash", json_string(hash_value) );
        json_array_append(hash, this_hash);
      }
      
      r2cmd(r2, "q");
      r2p_close(r2);

    }
  } else {
    /* Assign the content of the json */
    imports_obj->data = json_object_get(json, "imports");
    sections_obj->data = json_object_get(json, "sections");
    resources_obj->data = json_object_get(json, "resources");
    lib_obj->data = json_object_get(json, "libs");
    export_obj->data = json_object_get(json, "exports"); //TODO to review
    //bin_obj->data = json_object_get(json, "bins");
    info = json_object_get(json, "info");
    hash = json_object_get(json, "hash");

  }
   
  /* Resources array */
  json_array_foreach((json_t*)resources_obj->data, index, value)
  {
    
    set_integer(json_integer_value(json_object_get(value, "size")), 
               module_object, "resources[%i].size", index);
    set_integer(json_integer_value(json_object_get(value, "paddr")), 
               module_object, "resources[%i].paddr", index);
    set_string(json_string_value(json_object_get(value, "lang")), 
               module_object, "resources[%i].lang", index);
    set_string(json_string_value(json_object_get(value, "type")), 
               module_object, "resources[%i].type", index);
  }
  set_integer(index, module_object, "number_of_resources");


  /* End resources array */
  /* Section array */
  json_array_foreach((json_t*)sections_obj->data, index, value)
  {
    
    set_string(json_string_value(json_object_get(value, "name")), 
               module_object, "sections[%i].name", index);

    set_string(json_string_value(json_object_get(value, "flags")), 
               module_object, "sections[%i].flags", index);
    
    set_integer(json_integer_value(json_object_get(value, "size")), 
               module_object, "sections[%i].size", index);

    set_integer(json_integer_value(json_object_get(value, "vsize")), 
               module_object, "sections[%i].vsize", index);

    set_integer(json_integer_value(json_object_get(value, "paddr")), 
               module_object, "sections[%i].paddr", index);

  }
  set_integer(index, module_object, "number_of_sections");
  /* End section array */

  /* Exports array */
  json_array_foreach((json_t*)export_obj->data, index, value)
  {
    set_string(json_string_value(json_object_get(value, "name")), 
               module_object, "exports[%i].name", index);
    set_string(json_string_value(json_object_get(value, "demname")), 
               module_object, "exports[%i].demname", index);
    set_string(json_string_value(json_object_get(value, "flagname")), 
               module_object, "exports[%i].flagname", index);
    set_integer(json_integer_value(json_object_get(value, "paddr")), 
               module_object, "exports[%i].paddr", index);
    set_string(json_string_value(json_object_get(value, "type")), 
               module_object, "exports[%i].type", index);
    set_integer(json_integer_value(json_object_get(value, "vaddr")), 
               module_object, "exports[%i].vaddr", index);
    set_integer(json_integer_value(json_object_get(value, "size")), 
               module_object, "exports[%i].size", index);
  }
  set_integer(index, module_object, "number_of_exports");

  /* Definition of info variables */ 
  set_integer(json_boolean_value(json_object_get(info, "havecode")), 
             info_obj, "havecode");
  set_integer(json_boolean_value(json_object_get(info, "pic")), 
           info_obj, "pic");
  set_integer(json_boolean_value(json_object_get(info, "canary")), 
           info_obj, "canary");
  set_integer(json_boolean_value(json_object_get(info, "nx")), 
           info_obj, "nx");
  set_integer(json_boolean_value(json_object_get(info, "crypto")), 
           info_obj, "crypto");
  set_integer(json_boolean_value(json_object_get(info, "va")), 
           info_obj, "va");
  set_string(json_string_value(json_object_get(info, "intrp")),
          info_obj, "intrp");
  set_string(json_string_value(json_object_get(info, "bintype")),
          info_obj, "bintype");
  set_string(json_string_value(json_object_get(info, "class")),
          info_obj, "class");
  set_string(json_string_value(json_object_get(info, "lang")),
          info_obj, "lang");
  set_string(json_string_value(json_object_get(info, "arch")),
          info_obj, "arch");
  set_integer(json_integer_value(json_object_get(info, "bits")), 
           info_obj, "bits");
  set_string(json_string_value(json_object_get(info, "machine")),
          info_obj, "machine");
  set_string(json_string_value(json_object_get(info, "os")),
          info_obj, "os");
  set_integer(json_integer_value(json_object_get(info, "minopsz")), 
           info_obj, "minopsz");
  set_integer(json_integer_value(json_object_get(info, "maxopsz")), 
           info_obj, "maxopsz");
  set_integer(json_integer_value(json_object_get(info, "pcalign")), 
           info_obj, "pcalign");
  set_string(json_string_value(json_object_get(info, "subsys")),
          info_obj, "subsys");
  set_string(json_string_value(json_object_get(info, "endian")),
          info_obj, "endian");
  set_integer(json_boolean_value(json_object_get(info, "stripped")), 
           info_obj, "stripped");
  set_integer(json_boolean_value(json_object_get(info, "static")), 
           info_obj, "static");
  set_integer(json_boolean_value(json_object_get(info, "linenum")), 
           info_obj, "linenum");
  set_integer(json_boolean_value(json_object_get(info, "lsyms")), 
           info_obj, "lsyms");
  set_integer(json_boolean_value(json_object_get(info, "relocs")), 
           info_obj, "relocs");
  set_integer(json_integer_value(json_object_get(info, "binsz")), 
           info_obj, "binsz");
  set_string(json_string_value(json_object_get(info, "rpath")),
          info_obj, "rpath");
  set_string(json_string_value(json_object_get(info, "compiled")),
          info_obj, "compiled");
  set_string(json_string_value(json_object_get(info, "dbg_file")),
          info_obj, "dbg_file");
  set_string(json_string_value(json_object_get(info, "guid")),
          info_obj, "guid");
  /* End of info definition */
  
  /* Hashes definition */
  json_array_foreach(hash, index, value)
  {
    set_string(json_string_value(json_object_get(value, "hash")), 
               hash_obj, 
               json_string_value(json_object_get(value, "name")));
  }
  /* end of hashes definition */

  return ERROR_SUCCESS;
  
}

int module_unload(YR_OBJECT* module)
{
  YR_OBJECT* obj = NULL;

  if (module->data != NULL)
    json_decref((json_t*) module->data);

  obj = get_object(module, "imports");
  if (obj->data != NULL) {
    json_decref((json_t*) obj->data);    
  }
  obj = get_object(module, "section");
  if (obj->data != NULL) {
    json_decref((json_t*) obj->data);    
  }
  obj = get_object(module, "resources");
  if (obj->data != NULL) {
    json_decref((json_t*) obj->data);    
  }
  obj = get_object(module, "lib");
  if (obj->data != NULL) {
    json_decref((json_t*) obj->data);    
  }
  obj = get_object(module, "exports");
  if (obj->data != NULL) {
    json_decref((json_t*) obj->data);    
  }
  obj = get_object(module, "info");
  if (obj->data != NULL) {
    json_decref((json_t*) obj->data);    
  }
  obj = get_object(module, "hash");
  if (obj->data != NULL) {
    json_decref((json_t*) obj->data);    
  }

  //TODO, free some more pending memory
  return ERROR_SUCCESS;
}
