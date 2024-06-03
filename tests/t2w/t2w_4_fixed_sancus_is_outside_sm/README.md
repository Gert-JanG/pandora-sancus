From Tale of Two worlds paper:

```
We found both logical errors and integer overflow vul-
nerabilities in the sancus_is_outside_sm() function provided by the
trusted runtime. Particularly, the current implementation does not
properly detect an untrusted buffer that spans the entire enclave
address range, or a carefully crafted length specifier that triggers
an integer overflow to wrap around the 16-bit address space.
```

THIS TEST USES THE PATCHED VERSION OF sancus\_is\_outside\_sm()
this is reported by our PointerSanitizationPlugin, see main\_PointerSanitizationPlugin.html 
