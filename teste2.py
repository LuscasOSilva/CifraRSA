print(hex(0x8b)[2:]+hex(0x6c)[2:])
print(hex(int("11111111", 2)))
mesage = "Ola bom dia como vc esta tudo bem"

if (len(mesage)-1) % 16 != 0:
    mesage = mesage + (((16 - len(mesage)) % 16) * " ")

for block in range(0, len(mesage), 16):
    bit_sequence = ""
    for byte_sequence in mesage[block:block+16].encode('utf-8'):
        bit_sequence += f'{byte_sequence:08b}'
    print(mesage[block:block+16])
    print(bit_sequence)
    
    byte_sequence = int(bit_sequence, 2).to_bytes((len(bit_sequence) + 7) // 8, 'big')
    string = byte_sequence.decode('utf-8')

    print(string)  # Output: "comi teu pai"
'''
for b in "café".encode("latin-1"):
    print(f'{b:08b}  {bin(b)}')
'''