From Tale of Two worlds paper:

```
Sancus. We reviewed the assembly code inserted at the entry
point of a Sancus enclave, and noticed that the Sancus TEE suffers
from similar call stack switching vulnerabilities. Particularly, we
experimentally confirmed that it is possible to supply illegal CPU
register arguments and trick the enclave into “returning” into a
thread that was not waiting for a previous ocall return. In such a
case, the enclave stack will be falsely restored to the value of the
last valid ocall , leading to memory-safety violations from incorrect
control flow and register values. Sancus’s enclave entry assembly
routine further expects a CPU register parameter to specify the
address where execution is continued after leaving the enclave. The
software does not properly validate this parameter. Unlike SGX’s
eexit hardware primitive, which refuses to jump to illegal continu-
ation addresses, Sancus enclaves are exited by means of an ordinary
jmp instruction. We experimentally confirmed the possibility of
code reuse attacks [41] by forcing the vulnerable entry routine to
jump to an arbitrary in-enclave continuation address.
```

this is reported by our PointerSanitizationPlugin, see main\_ControlFlowSanitizationPlugin.html 
