The challenge is an archive of system files. Searching for recently edited files we find a crashdump of sshd service.
```
C:\Users\flare\Desktop\sshd(1)\ssh_container> Get-ChildItem -re -in * |`
Where-Object {$_.Length -ge 1 }|`
sort LastWriteTime -descending|`
select -first 50
```

![[../attachments/Screenshot-from-2025-01-27-11-14-32.png]]

Looking at the crashdump in GDB we see that it crashed in liblzma while trying to resolve RSA_public_decrypt.!
![[../attachments/Pasted-image-20250127112113.png]]
Liblzma is not mapped in the crashdump, but we can get it from the system archive and rebase it to the same address.
![[../attachments/Pasted-image-20250127112233.png]]
The function looks like a hook on RSA_public_decrypt, it takes the same parameters, runs some code and tries to return to the original function. This is similar to the backdoor in xz  
(https://www.openwall.com/lists/oss-security/2024/03/29/4).

```
int RSA_public_decrypt(int flen, unsigned char *from,
   unsigned char *to, RSA *rsa, int padding);
   
_RSA_public_decrypt()_ recovers the message digest from the **flen** bytes long signature at **from** using the signer's public key **rsa**.
```
In the challenge the backdoor is activated when the function receives as a parameter a signature starting with `48 7a 40 c5`. It then reads a key and nonce from the signature and decrypts a shellcode using standard ChaCha20.
![[../attachments/Pasted-image-20250127113529.png]]
The signature containing the key and nonce can be found in the crashdump.
![[../attachments/Pasted-image-20250127123731.png]]
The decrypted shellcode connects to a socket using a hardcoded ip and port number. It receives a key, nonce, length of a filename and a filename. It then reads from the given file, encrypts the data using ChaCha20 and sends it to the socket.
![[../attachments/Pasted-image-20250127114343.png]]
![[../attachments/Pasted-image-20250127124033.png]]
Searching the stack area in the crashdump we find what could potentially be the filename. From the disassembly we know that the key and nonce are placed above the filename on  the stack and the encrypted data starts 0x100 bytes below the start of the filename.
![[Pasted-image-20250127115605.png]]
The ChaCha20 implementation looks very similar to an opensource one from github (https://github.com/Ginurx/chacha20-c) but trying the decryption with the recovered data doesn't work.
![[../attachments/Pasted-image-20250127114553.png]]

![[../attachments/Pasted-image-20250127114608.png]]

![[../attachments/Pasted-image-20250127114626.png]]
![[../attachments/Pasted-image-20250127114713.png]]
![[../attachments/Pasted-image-20250127114746.png]]
I didn't know what I was missing in the decryption, so I decided to emulate the whole shellcode instead.
```
from unicorn import *
from unicorn.x86_const import *

key = bytes.fromhex('8dec9112eb760eda7c7d87a443271c35d9e0cb878993b4d904aef934fa2166d7')
nonce = bytes.fromhex('111111111111111111111111')
data = bytes.fromhex('a9f63408422a9e1c0c03a8089470bb8daadc6d7b24ff7f247cda839e92f7071d0263902ec1580000')
length = bytes.fromhex('00000028')    

# Unicorn emulator setup
uc = Uc(UC_ARCH_X86, UC_MODE_64)

stack_base = 0x00100000
stack_size = 0x00100000

# Position the stack pointer in the middle of the stack
RSP = stack_base + (stack_size // 2)

# Map the stack memory into the emulator
uc.mem_map(stack_base, stack_size)

# Fill the stack memory with null bytes
uc.mem_write(stack_base, b"\x00" * stack_size)

# Write data to stack
uc.mem_write(stack_base+0x1000, key)
uc.mem_write(stack_base+0x2000, nonce)
uc.mem_write(stack_base+0x3000, data)
uc.mem_write(stack_base+0x4500, length)

# Set the stack pointer
uc.reg_write(UC_X86_REG_RSP, RSP)

setup_offset = 3282
setup_len = 118
xor_offset = 3401
xor_len = 119


target_base = 0x00400000
target_size = 0x00100000

# Map target memory with r/w/x permissions
uc.mem_map(target_base, target_size, UC_PROT_ALL)

# Fill the target memory with null bytes
uc.mem_write(target_base, b"\x00" * target_size)

# Write our code into the target memory
uc.mem_write(target_base, code)

uc.reg_write(UC_X86_REG_RAX, stack_base+0x4000) #ctx
print(f"ctx: {uc.mem_read(stack_base+0x4000, 0xc0).hex()}")
uc.reg_write(UC_X86_REG_RDX, stack_base+0x1000) #key
print(f"key: {uc.mem_read(stack_base+0x1000, 0x20).hex()}")
uc.reg_write(UC_X86_REG_RCX, stack_base+0x2000) #nonce
print(f"nonce: {uc.mem_read(stack_base+0x2000, 0xc).hex()}")
uc.reg_write(UC_X86_REG_R8, 0)
print("Running key setup...")
uc.emu_start(target_base + setup_offset, target_base + setup_offset + setup_len, timeout=0, count=0)

uc.reg_write(UC_X86_REG_RAX, stack_base+0x4000) #ctx
print(f"ctx: {uc.mem_read(stack_base+0x4000, 0xc0).hex()}")
print(uc.mem_read(stack_base+0x4000, 0xc0).hex())
uc.reg_write(UC_X86_REG_RDX, stack_base+0x3000) #data
print(f"data: {uc.mem_read(stack_base+0x3000, 0x28).hex()}")
uc.reg_write(UC_X86_REG_RCX, stack_base+0x4500) #len
print(f"len: {uc.mem_read(stack_base+0x4500, 0x4).hex()}")
print("Running decryption...")
uc.emu_start(target_base + xor_offset, target_base + xor_offset + xor_len, timeout=0, count=0)

print("Done")

EAX = uc.reg_read(UC_X86_REG_EAX)
print(f"eax: {EAX}")
print(f"ctx: {uc.mem_read(stack_base+0x4000, 0xc0).hex()}")
decr = uc.mem_read(stack_base+0x3000, 0x28)
print(f"decrypted data: {decr.hex()}")

```
While emulating the shellcode with unicorn, the keystream generation part worked correctly but the decryption didn't. Fortunately, the keystream is enough to decrypt the data with just a manual xor.
```
python3 emulate.py
ctx: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
key: 8dec9112eb760eda7c7d87a443271c35d9e0cb878993b4d904aef934fa2166d7
nonce: 111111111111111111111111
Running key setup...
ctx: 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000008dec9112eb760eda7c7d87a443271c35d9e0cb878993b4d904aef934fa2166d7111111111111111111111111000000000000000000000000657870616e642033322d62797465204b8dec9112eb760eda7c7d87a443271c35d9e0cb878993b4d904aef934fa2166d700000000111111111111111111111111
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000008dec9112eb760eda7c7d87a443271c35d9e0cb878993b4d904aef934fa2166d7111111111111111111111111000000000000000000000000657870616e642033322d62797465204b8dec9112eb760eda7c7d87a443271c35d9e0cb878993b4d904aef934fa2166d700000000111111111111111111111111
data: a9f63408422a9e1c0c03a8089470bb8daadc6d7b24ff7f247cda839e92f7071d0263902ec1580000
len: 00000028
Running decryption...
Done
eax: 1
ctx: da8344787353c17f64629966cb03cee3cee8143b42931e5619f7ecf0bc94687008e5c843750d35477548a3b2ceed7aaa802b75b0ba7e29b3448e721eb7c2835601000000000000008dec9112eb760eda7c7d87a443271c35d9e0cb878993b4d904aef934fa2166d7111111111111111111111111000000000000000000000000657870616e642033322d62797465204b8dec9112eb760eda7c7d87a443271c35d9e0cb878993b4d904aef934fa2166d700000000111111111111111111111111
decrypted data: 73f63408422a9e1c0c03a8089470bb8daadc6d7b24ff7f247cda839e92f7071d0263902ec1580000
```

```
emit hex:a9f63408422a9e1c0c03a8089470bb8daadc6d7b24ff7f247cda839e92f7071d0263902ec1580000 | xor hex:da8344787353c17f64629966cb03cee3cee8143b42931e5619f7ecf0bc94687008e5c843750d35477548a3b2ceed7aaa802b75b0ba7e29b3448e721eb7c2835601000000000000008dec9112eb760eda7c7d87a443271c35d9e0cb878993b4d904aef934fa2166d7111111111111111111111111000000000000000000000000657870616e642033322d62797465204b8dec9112eb760eda7c7d87a443271c35d9e0cb878993b4d904aef934fa2166d700000000111111111111111111111111
supp1y_cha1n_sund4y@flare-on.com
�Xm�U5G

```

