mod_form is an example module that modifies or unsets form data pairs according
to rules that are configured.

## Dependencies
* mod_request
* IHS 9.0 and above / Apache 2.4.x and above

## Building the module
The module can be built using `apxs` like so:
```
/path/to/bin/apxs -ci src/mod_form.c
```

## Module directives
* `FormData unset <name-regex>` unsets all form pairs that match the regex
  `name-regex`.
* `FormData edit <name> <pattern> <substitution>` replaces the value of the
  form pair `name` with the value of `substitution` if the value matches the
  regex provided in `pattern`.

## Examples
### Unsetting all pairs starting with `unset_`
```
LoadModule request_module modules/mod_request.so
LoadModule form_module modules/mod_form.so

<Location />
  KeptBodySize 2048
  FormData unset unset_.*
</Location>
```

### Editing usernames to remove the prefix `admin_`
```
LoadModule request_module modules/mod_request.so
LoadModule form_module modules/mod_form.so

<Location />
  KeptBodySize 2048
  FormData edit username ^admin_(.*) $1
</Location>
```

