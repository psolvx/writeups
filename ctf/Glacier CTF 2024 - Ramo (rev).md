The challenge consists of an encrypted file `flag.txt.enc` and a 64 bit Windows executable. The program encrypts a given file and saves the encrypted data with an appended `.enc` extension.

The program first generates a part of the seed from system time.
![[Pasted image 20250127135133.png]]
Second part of the seed is generated from transformed characters of the filename. Both parts are then xor'ed and used to generate a 32 bytes long key and a 16 bytes long iv.
![[Pasted image 20250127135321.png]]
The prng function uses a lot of combined operations in a loop and is probably impossible to reverse.
![[Pasted image 20250127140309.png]]
In the aes key setup only 16 bytes of the generated key are used.
![[Pasted image 20250127135920.png]]

Each byte of the seed is transformed with some arithmetic operations into a 4 byte value. It is then saved to the output file followed by the next 16 bytes of the encrypted data. 

![[Pasted image 20250127135507.png]]
The arithmetic operations used to obfuscate the seed are not as complex as a prng and can be reversed. I wrote a python script to recover the seed from the encrypted file.
```
def parse_file(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    # Extract 4-byte values as integers (little-endian)
    return [int.from_bytes(data[i:i+4], byteorder='little') for i in range(0, len(data), 20)]

def reverse_var(final_var, chars='flag.txt'):
    MOD = 2**32
    MOD_INV_0x21 = 0x3e0f83e1 # Precomputed modular inverse of 0x21 mod 2^32

    for char in reversed(chars):
        final_var = (final_var - ord(char)) % MOD  # Undo addition of ASCII value
        final_var = (final_var * MOD_INV_0x21) % MOD  # Undo multiplication by 0x21
    # Undo the initial addition of 0x1505
    seed_byte = (final_var - 0x1505) % MOD
    return seed_byte & 0xFF  # Return the least significant byte (original seed byte)

def reverse_seed(filename):
    final_vars = parse_file(filename)
    seed = []
    for final_var in final_vars:
        seed_byte = reverse_var(final_var)
        seed.append(seed_byte)
    return seed

filename = 'flag.txt.enc'
print(parse_file(filename))
seed = reverse_seed(filename)
print("Recovered seed:", seed)
for c in seed:
    print(hex(c))

```
The recovered seed is `55 75 52 12`.

To get the key and iv used for aes decryption the value of the seed can be patched in the r15 register before calls to the prng function. The calls will then return the correct key and iv.

![[Pasted image 20250127135054.png]]

The recovered key and iv can then be used to decrypt the message extracted from the encrypted file.

```
>emit hex:11A8615B0B2F96697E9782DB2781E80719C8ABE3BA6ABEC833EDCB7EC7C574938B995F5BEA14BADEAF111B401679B0E3A3F001923AA9DC17F1BB0BDA10907C51 | aes hex:556E6B5D6E38266F373E415A464E794E -i hex:50365177676B7865484B597A623A476B -L                                                                                   gctf{i_h0p3_y0u_used_th3_c0rrect_r4nd0m_funct10n_s0lv1Ng_th1s!!} 
```