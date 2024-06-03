From Tale of Two worlds paper:

```
A second input pointer validation vulnerability was found in
an infrastructural trusted loader enclave [14] that decrypts third-
party application enclaves to preserve code confidentiality. We
noticed that the trusted loader enclave code lacks any input pointer
validation checks, allowing us to build an arbitrary write primitive
in enclave memory. We successfully exploited this vulnerability in
a PoC that launches a ROP-style [41] control flow hijacking attack
by corrupting the loader enclave call stack.
```

this is reported by our PointerSanitizationPlugin, see main\_PointerSanitizationPlugin.html 
