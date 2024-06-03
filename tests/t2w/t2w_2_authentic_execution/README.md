From Tale of Two worlds paper:

```
A first critical vulnerability was found in a recent extension [31]
to the Sancus compiler infrastructure, which implements a high-
level authenticated message passing abstraction to develop dis-
tributed event-driven enclave programs. Much like Intel’s edger8r ,
the Sancus compiler fully automatically generates ecall bridge code
to transparently marshal, decrypt, and authenticate input buffers,
which can be subsequently processed by the shielded application.
We found that the compiler-generated bridge code does not sani-
tize untrusted pointer arguments (cf. Appendix A.5). This may be
exploited to forcefully decrypt enclave secrets.
```

this is reported by our PointerSanitizationPlugin, see main\_PointerSanitizationPlugin.html 
