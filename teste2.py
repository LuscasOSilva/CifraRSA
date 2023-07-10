'''
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

    print(string)  # Output:
'''
'''
for b in "café".encode("latin-1"):
    print(f'{b:08b}  {bin(b)}')
'''
import base64

bytes_data = b'\xcc\xf4\xaaz\x7f3\xc8b+w\xef\x92c\x05\xc9Y\x8a\x0eg\xa0p\xf9\x80\xf4Q&\xcb\xa8\xbe\xd1\x03*\x9cj[\xcdL\x0f\xdcm\xb76F\xc4\xc9\xa2\xdf1M\xe4\x0ff5\x85U\x1c\x92\xae\x18\xa4\xf5\x18Y\x06\xa8\xb4\x04v\x01\xb8\xfa\xceV\xc0\xf5\t\xe5\x97\xbd\x15Z\xe4\xca:\xd4\x1aT\x15\x06\x8b\xbb.\xcf\xaf\xc5\xcd\xeb\x91'

base64_data = base64.b64encode(bytes_data).decode()
print(base64_data.decode())