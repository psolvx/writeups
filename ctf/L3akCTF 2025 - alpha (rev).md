
# Summary

This was a fun reverse engineering challenge from 2025 L3akCTF. I got the 11th solve out of 34. It is also the only challenge I solved and one of two I attempted, because I played alone and for a limited time. I hope to return to this ctf next year for more challenges.

This challenge also gave me a nice opportunity to practice symbolic execution using triton which is I think more fun than asking an LLM to translate decompilation into z3 constraints. 

![../attachments/Pasted%20image%2020250715120925.png](attachments/Pasted%20image%2020250715120925.png)

# Analysis

After reading the <del>cringe</del> unhelpful description we examine the program. It is a 64-bit ELF binary.

```
file chal
chal: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=778ac9952dc572348481162893656dfc9f55edab, for GNU/Linux 3.2.0, stripped
```

Opening the program in binary ninja we see that it calls `printf` and `fgets` followed by an instruction that was not disassembled properly - most likely an illegal instruction.

![../attachments/Pasted%20image%2020250715121514.png](attachments/Pasted%20image%2020250715121514.png)

Following the `data_404010` reference which is the argument to `printf` we see that it asks for a flag. The other two strings being `Correct!` and `Incorrect!` indicate that this is a flag-checker challenge.

![../attachments/Pasted%20image%2020250715121538.png](attachments/Pasted%20image%2020250715121538.png)

Knowing that there is an illegal instruction i start looking for registered signal handler. In this case it has to be before main function so probably inside one of the `INIT` functions.

The function `_INIT_1` is seen registering a signal handler `sub_4011e9` using the `sigaction` syscall. The argument `signum = 4` corresponds to `SIGILL` (illegal instruction) which is what we are looking for.

![../attachments/Pasted%20image%2020250715121608.png](attachments/Pasted%20image%2020250715121608.png)

The handler is fairly simple. It transforms the first 0x40 bytes of main by xoring them with a key stored in the data section. Each time the handler is called, the next part of the key is used. The key in .rodata section is 0x974 bytes long, indicating that the handler will be called multiple times.

It also sets the last byte to 0x37 which is the same value that caused the illegal instruction in the first place and returns the address of this byte.

![../attachments/Pasted%20image%2020250715121651.png](attachments/Pasted%20image%2020250715121651.png)

We can even improve the decompilation a bit by adding the type definition for `ucontext_t`.

As can be confirmed in `/usr/include/sys/ucontext.h`, position 0x11 in the general registers array corresponds to the instruction pointer. This makes it so that after the handler finishes, execution is transferred to the start of the modified main function.

![../attachments/Pasted%20image%2020250715140013.png](attachments/Pasted%20image%2020250715140013.png)

The other functions in the program appear to be obfuscated math operations but they have no cross references. They will possibly be called by the modified main code.

# Solution

My favorite way of solving flag-checker challenges is to use symbolic execution. It is not always the best choice but here it seems good because there is not a lot of system calls or external library calls to emulate, and no complex instructions like floating point operations etc.

To write the solver i used Triton dynamic binary analysis library and TritonDSE which is a higher level wrapper for Triton. The documentation can be found here:
- triton: https://triton-library.github.io/documentation/doxygen/
- tritondse: https://quarkslab.github.io/tritondse/tutos/starting.html

Previously i had some issues when installing tritondse with different python and lief versions, so here is the environment i used now:
```
requires-python = ">=3.11.12"
dependencies = [
    "triton-library>=1.0.0rc4",
    "tritondse>=0.1.12",
    "z3-solver>=4.15.0.0",
    "lief==0.16.6",
    "cle==9.2.161",
]
```

To start we want to load the program and view the instruction
trace. This code is taken straight from tritondse documentation

```python
from tritondse import *
import logging
import tritondse.logging
from triton import *

logging.basicConfig(level=logging.DEBUG)
tritondse.logging.enable()

p = Program("./chal")
config = Config(pipe_stdout=True, seed_format=SeedFormat.COMPOSITE)
seed = Seed(CompositeData(files={"stdin": b"A"*0x40}))
executor = SymbolicExecutor(config, seed)
executor.load(p)

def trace_inst(se: SymbolicExecutor, pstate: ProcessState, inst: Instruction):
	print(f"0x{inst.getAddress():x}:{inst.getDisassembly()}")

executor.callback_manager.register_post_instruction_callback(trace_inst)

executor.emulate()
```

In the trace below we can see some important information:
- sigaction imported but unsupported - we have to emulate the signal handling mechanism
- program starts at 0x1100 - this is the entrypoint
- at 0x111f we can identify the call to main which starts at 0x1310
- we confirm that the instruction after 0x134f can't be disassembled correctly

```
arch ARCHITECTURES.X86_64
WARNING:tritondse.executor:symbol sigaction imported but unsupported
WARNING:tritondse.executor:symbol sigemptyset imported but unsupported
WARNING:tritondse.executor:symbol _ITM_deregisterTMCloneTable imported but unsupported
WARNING:tritondse.executor:symbol __gmon_start__ imported but unsupported
WARNING:tritondse.executor:symbol _ITM_registerTMCloneTable imported but unsupported
WARNING:tritondse.executor:symbol __cxa_finalize imported but unsupported
0x1100: endbr64
0x1104: xor ebp, ebp
0x1106: mov r9, rdx
0x1109: pop rsi
0x110a: mov rdx, rsp
0x110d: and rsp, 0xfffffffffffffff0
0x1111: push rax
0x1112: push rsp
0x1113: xor r8d, r8d
0x1116: xor ecx, ecx
0x1118: lea rdi, [rip + 0x1f1]
0x111f: call qword ptr [rip + 0x2eb3]
0x1310: push rbp
0x1311: mov rbp, rsp
0x1314: push r12
0x1316: push rbx
0x1317: sub rsp, 0x50
0x131b: mov byte ptr [rbp - 0x11], 1
0x131f: mov rax, qword ptr [rip + 0x2cea]
0x1326: mov rdi, rax
0x1329: mov eax, 0
0x132e: call 0x10d0
0x10d0: endbr64
0x10d4: jmp qword ptr [rip + 0x2ee6]
0x1333: mov rdx, qword ptr [rip + 0x2cf6]
0x133a: lea rax, [rbp - 0x60]
0x133e: mov esi, 0x40
0x1343: mov rdi, rax
0x1346: call 0x10e0
0x10e0: endbr64
0x10e4: jmp qword ptr [rip + 0x2ede]
0x134b: movzx eax, byte ptr [rbp - 0x57]
0x134f: nop
WARNING:tritondse.executor:Execution interrupted: x8664Cpu::disassembly(): Failed to disassemble the given code.
```

To emulate the signal handler mechanism i dumped the key from the challenge binary and wrote a simple hook which does the same transformation as the real handler. It uses a global index variable to keep track of the position in the key, reads memory from the current process state object, xors it with the key and writes it back. I also read the memory again and print it to verify that it is patched.

```python
with open("key.hex", "r") as f:
    key = bytes.fromhex(f.read().strip())

index = 0

def xor_block(a, b):
    for i in range(len(a)):
        a[i] ^= b[i]
    return a


def hook_transform_main(se: SymbolicExecutor, pstate: ProcessState, addr: int):
	global index
	print("[+] hooked main transform")
	
	mem_addr = 0x1310
	original = pstate.memory.read(mem_addr, 0x40)
	decrypted = xor_block(bytearray(original[:0x40]), key[index:index+0x40])
	index += 0x40
	print(f"writing to {hex(mem_addr)}")
	pstate.memory.write(mem_addr, decrypted)
	
	patched = pstate.memory.read(mem_addr, 0x40)
	print(patched.hex())
	
	executor.pstate.cpu.rip = 0x1310


executor.callback_manager.register_post_addr_callback(0x134f, hook_transform_main)
```

Running this script i got a longer trace but still ending in an illegal instruction this time after address 0x134d.

```
0x15b1: mov eax, dword ptr [rbp - 4]
0x15b4: add eax, edx
0x15b6: pop rbp
0x15b7: ret
0x1345: cmp eax, 0x1326
0x134a: sete al
0x134d: movzx edx, al
WARNING:tritondse.executor:Execution interrupted: x8664Cpu::disassembly(): Failed to disassemble the given code.
```

Because of different instruction lengths, the illegal instruction appeared at different addresses from 0x134c to 0x134f so I just added the callback on these addresses:

```python
executor.callback_manager.register_post_addr_callback(0x134c, hook_transform_main)

executor.callback_manager.register_post_addr_callback(0x134d, hook_transform_main)

executor.callback_manager.register_post_addr_callback(0x134e, hook_transform_main)

executor.callback_manager.register_post_addr_callback(0x134f, hook_transform_main)
```

This time the trace finishes and we see the `Incorrect!` message getting. It got printed by a call to puts (TritonDSE implements some of the common linux apis). We can confirm that by looking at RVA 0x10a0 in binary ninja which is in the .plt.sec section and matches our disassembly.

```
[+] hooked main transform
writing to 0x1310
807def007411488b05fb2c00004889c7e87bfdffffeb0f488b05f22c00004889c7e86afdffffb8000000004883c4505b415c5dc3909090909090909090909090
[0x1310: cmp byte ptr [rbp - 0x11], 0
[0x1314: je 0x1327
[0x1327: mov rax, qword ptr [rip + 0x2cf2]
[0x132e: mov rdi, rax
[0x1331: call 0x10a0
[0x10a0: endbr64
[0x10a4: jmp qword ptr [rip + 0x2efe]
Incorrect!
[0x1336: mov eax, 0
[0x133b: add rsp, 0x50
[0x133f: pop rbx
[0x1340: pop r12
[0x1342: pop rbp
[0x1343: ret
INFO:tritondse.executor:hit 0x1125: hlt instruction stop.
```

![../attachments/Pasted%20image%2020250715144631.png](attachments/Pasted%20image%2020250715144631.png)

To see both branches of the if statement i used binary-refinery asm unit to quickly disassemble the last patch to the main function. In the disassembly below we can see that both branches lead to a call to the same function (puts) with different arguments `[rip + 0x2cfb]` and `[rip + 0x2cf2]` which correspond to the addresses of `Correct` and `Incorrect` strings in the data section.

```
emit h:807def007411488b05fb2c00004889c7e87bfdffffeb0f488b05f22c00004889c7e86afdffffb8000000004883c4505b415c5dc3909090909090909090909090 | asm x64
0000:  cmp   byte ptr [rbp - 0x11], 0       ; 80 7D EF 00           .}..
0004:  je    0x17                           ; 74 11                 t.
0006:  mov   rax, qword ptr [rip + 0x2cfb]  ; 48 8B 05 FB 2C 00 00  H...,..
000D:  mov   rdi, rax                       ; 48 89 C7              H..
0010:  call  0xfffffffffffffd90             ; E8 7B FD FF FF        .{...
0015:  jmp   0x26                           ; EB 0F                 ..
0017:  mov   rax, qword ptr [rip + 0x2cf2]  ; 48 8B 05 F2 2C 00 00  H...,..
001E:  mov   rdi, rax                       ; 48 89 C7              H..
0021:  call  0xfffffffffffffd90             ; E8 6A FD FF FF        .j...
0026:  mov   eax, 0                         ; B8 00 00 00 00        .....
002B:  add   rsp, 0x50                      ; 48 83 C4 50           H..P
002F:  pop   rbx                            ; 5B                    [
0030:  pop   r12                            ; 41 5C                 A\
0032:  pop   rbp                            ; 5D                    ]
0033:  ret                                  ; C3                    .
0034:  nop                                  ; 90                    .
0035:  nop                                  ; 90                    .
0036:  nop                                  ; 90                    .
0037:  nop                                  ; 90                    .
0038:  nop                                  ; 90                    .
0039:  nop                                  ; 90                    .
003A:  nop                                  ; 90                    .
003B:  nop                                  ; 90                    .
003C:  nop                                  ; 90                    .
003D:  nop                                  ; 90                    .
003E:  nop                                  ; 90                    .
003F:  nop                                  ; 90                    .
```

Since we want to reach `Correct`, we want the `je` instruction to not jump, so `cmp   byte ptr [rbp - 0x11], 0` has to be false. To solve for that i wrote another hook. This one should only be executed on the final cmp instruction. It first checks if the value at `rbp - 0x11` is symbolic that is if it depends on any symbolic variables (our input). Then it tries to solve for this memory value to be not equal 0. To find the solution triton uses a smt solver like z3 or bitwuzla.

```python
def hook_cmp(se: SymbolicExecutor, pstate: ProcessState, inst: Instruction):
	if inst.getAddress() == 0x1310 and inst.getDisassembly() == "cmp byte ptr [rbp - 0x11], 0":
		print("[+] solving")
		rbp = pstate.cpu.rbp
		print(f"[+] Byte at [rbp - 0x11] is symbolic? {pstate.is_memory_symbolic(rbp - 0x11, 1)}")
		sym_val = pstate.read_symbolic_memory_int(rbp - 0x11, 1)
	
	status, model = pstate.solve(sym_val.getAst() != 0)
	
	print(f"[+] status {status}")
	if status == SolverStatus.SAT:
		var_values = pstate.get_expression_variable_values_model(sym_val, model)
		for var, value in var_values.items():
			print(var, value)

executor.callback_manager.register_post_instruction_callback(hook_cmp)
```

Unfortunately running this code results in UNSAT.
```
[+] solving
[+] Byte at [rbp - 0x11] is symbolic? True
[+] status 0
```

![../attachments/Pasted%20image%2020250715131211.png](attachments/Pasted%20image%2020250715131211.png)

To debug why we are failing we can try to print the path constraints for the process state at the final hook.

```python
print("[+] Dumping constraints:")
	for i, constraint in enumerate(pstate.get_path_constraints()):
	print(f"[{i}] {constraint.getBranchConstraints()}")
```

This results in 135 constraints like the ones below, all referencing the same addresses.

```
[*] Dumping constraints:
[0] [{'isTaken': True, 'srcAddr': 5541, 'dstAddr': 5510, 'constraint': (= ref!8190 (_ bv0 1))}, {'isTaken': False, 'srcAddr': 5541, 'dstAddr': 5543, 'constraint': (not (= ref!8190 (_ bv0 1)))}]
[1] [{'isTaken': True, 'srcAddr': 5541, 'dstAddr': 5510, 'constraint': (= ref!8263 (_ bv0 1))}, {'isTaken': False, 'srcAddr': 5541, 'dstAddr': 5543, 'constraint': (not (= ref!8263 (_ bv0 1)))}]
[2] [{'isTaken': True, 'srcAddr': 5541, 'dstAddr': 5510, 'constraint': (= ref!8336 (_ bv0 1))}, {'isTaken': False, 'srcAddr': 5541, 'dstAddr': 5543, 'constraint': (not (= ref!8336 (_ bv0 1)))}]
```

The addresses correspond to the function below. Here the variable `i` which is the loop counter that seems to be causing problems depends on the argument to the function.

![../attachments/Pasted%20image%2020250715125956.png](attachments/Pasted%20image%2020250715125956.png)

To get a better trace i update the trace hook to show the arguments of all the obfuscated math functions when they are called but not to show the trace inside them because it was to long to read the disassembly loops.

```python
depth = 0

def trace_inst(se: SymbolicExecutor, pstate: ProcessState, inst: Instruction):
	global depth
	if depth < 4:
		print(f"[0x{inst.getAddress():x}: {inst.getDisassembly()}")
	if "call" in inst.getDisassembly():
		depth += 1
	elif "ret" in inst.getDisassembly():
		depth -= 1
	
	funcs = [0x1381, 0x1401, 0x153b, 0x15b8, 0x164a, 0x16c8, 0x1728]
	
	for i, f in enumerate(funcs):
	if inst.getAddress() == f:
		print(f"[+] Calling function {i+1}")
		print(f"edi: {pstate.is_register_symbolic('edi')}{pstate.read_symbolic_register('edi')}")
		print(f"esi: {pstate.is_register_symbolic('esi')}{pstate.read_symbolic_register('esi')}")
```

It turned out that the arguments are symbolic, so I guessed that the symbolic loop counter somehow breaks symbolic execution.

```
[+] Calling function 3
edi: True (define-fun ref!210939 () (_ BitVec 32) ((_ extract 31 0) ref!210925))
esi: True (define-fun ref!210940 () (_ BitVec 32) ((_ extract 31 0) ref!210923))
```

I decided that since only one of the functions has a loop counter depending on the symbolic argument I could just replace it with a stub implementation. The function turned out to be an obfuscated multiplication which was easy to implement, i just needed to get the arguments, multiply them and save to rax and emulate a return.

```python
def stub_mul(se: SymbolicExecutor, pstate: ProcessState, addr: int):
	arg1_sym = pstate.read_symbolic_register('rdi')
	arg2_sym = pstate.read_symbolic_register('rsi')
	ctx = pstate.actx
	arg1_ast = arg1_sym.getAst()
	arg2_ast = arg2_sym.getAst()
	
	result_ast = ctx.bvmul(arg1_ast, arg2_ast)
	pstate.write_symbolic_register('rax', result_ast)
	
	ret_addr = pstate.memory.read_int(pstate.cpu.rsp)
	pstate.cpu.rip = ret_addr
	pstate.cpu.rsp += 8
	
	global depth
	depth -= 1

executor.callback_manager.register_post_addr_callback(0x153b, stub_mul)
```

With these changes I finally got a SAT result. To get the flag as a string I modified the code:

```python
if status == SolverStatus.SAT:
	var_values = pstate.get_expression_variable_values_model(sym_val, model)
	flag = [" "]*0x40
	for var, value in var_values.items():
		flag[int(var.getName().split('_')[1])] = chr(value)
		print(''.join(flag))
```

```
[+] solving
[+] Byte at [rbp - 0x11] is symbolic? True
[+] status 1
L3AK{R3m0V&_Qu@n~iF!3rs}
Incorrect!
INFO:tritondse.executor:hit 0x1125: hlt instruction stop.
```

By checking against the program we confirm that the flag is correct. The incorrect message is because we are only solving it symbolically. To also print the correct message we could simply set the zero flag after solving by using `pstate.cpu.zf = 0`.

# Full solver script
```python
from tritondse import *
import logging
import tritondse.logging
from triton import *

logging.basicConfig(level=logging.DEBUG)
tritondse.logging.enable()

p = Program("./chal")

config = Config(pipe_stdout=True, seed_format=SeedFormat.COMPOSITE)
seed = Seed(CompositeData(files={"stdin": b"A"*0x40}))

executor = SymbolicExecutor(config, seed)
executor.load(p)
 
depth = 0

def trace_inst(se: SymbolicExecutor, pstate: ProcessState, inst: Instruction):
    global depth
    if depth < 4:
        print(f"[0x{inst.getAddress():x}: {inst.getDisassembly()}")
    if "call" in inst.getDisassembly():
        depth += 1
    elif "ret" in inst.getDisassembly():
        depth -= 1

    funcs = [0x1381, 0x1401, 0x153b, 0x15b8, 0x164a, 0x16c8, 0x1728]
    for i, f in enumerate(funcs):
        if inst.getAddress() == f:
            print(f"[+] Calling function {i+1}")
            print(f"edi: {pstate.is_register_symbolic('edi')} {pstate.read_symbolic_register('edi')}")
            print(f"esi: {pstate.is_register_symbolic('esi')} {pstate.read_symbolic_register('esi')}")

executor.callback_manager.register_post_instruction_callback(trace_inst)


with open("key.hex", "r") as f:
    key = bytes.fromhex(f.read().strip())

index = 0

def xor_block(a, b):
    for i in range(len(a)):
        a[i] ^= b[i]
    return a


def hook_transform_main(se: SymbolicExecutor, pstate: ProcessState, addr: int):
    global index
    print("[+] hooked main transform")

    mem_addr = 0x1310
    original = pstate.memory.read(mem_addr, 0x40)
    decrypted = xor_block(bytearray(original[:0x40]), key[index:index+0x40])
    index += 0x40
    print(f"writing to {hex(mem_addr)}")
    pstate.memory.write(mem_addr, decrypted)

    patched = pstate.memory.read(mem_addr, 0x40)
    print(patched.hex())
    
    executor.pstate.cpu.rip = 0x1310


executor.callback_manager.register_post_addr_callback(0x134c, hook_transform_main)
executor.callback_manager.register_post_addr_callback(0x134d, hook_transform_main)
executor.callback_manager.register_post_addr_callback(0x134e, hook_transform_main)
executor.callback_manager.register_post_addr_callback(0x134f, hook_transform_main)


def hook_cmp(se: SymbolicExecutor, pstate: ProcessState, inst: Instruction):
    if inst.getAddress() == 0x1310 and inst.getDisassembly() == "cmp byte ptr [rbp - 0x11], 0":
        print("[*] Dumping constraints:")
        for i, constraint in enumerate(pstate.get_path_constraints()):
            print(f"[{i}] {constraint.getBranchConstraints()}")

        print("[+] solving")
        rbp = pstate.cpu.rbp
        print(f"[+] Byte at [rbp - 0x11] is symbolic? {pstate.is_memory_symbolic(rbp - 0x11, 1)}")
        
        sym_val = pstate.read_symbolic_memory_int(rbp - 0x11, 1)
        status, model = pstate.solve(sym_val.getAst() != 0)
        pstate.cpu.zf = 0
        print(f"[+] status {status}")
        
        if status == SolverStatus.SAT:
            var_values = pstate.get_expression_variable_values_model(sym_val, model)
            flag = [" "]*0x40
            for var, value in var_values.items():
                flag[int(var.getName().split('_')[1])] = chr(value)
            print(''.join(flag))

executor.callback_manager.register_post_instruction_callback(hook_cmp)


def stub_mul(se: SymbolicExecutor, pstate: ProcessState, addr: int):
    global depth
    arg1_sym = pstate.read_symbolic_register('rdi')
    arg2_sym = pstate.read_symbolic_register('rsi')
    
    ctx = pstate.actx
    arg1_ast = arg1_sym.getAst()
    arg2_ast = arg2_sym.getAst()
    result_ast = ctx.bvmul(arg1_ast, arg2_ast)

    pstate.write_symbolic_register('rax', result_ast)

    ret_addr = pstate.memory.read_int(pstate.cpu.rsp)
    pstate.cpu.rip = ret_addr
    pstate.cpu.rsp += 8
    depth -= 1

executor.callback_manager.register_post_addr_callback(0x153b, stub_mul)

executor.emulate()
```