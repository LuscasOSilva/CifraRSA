# Função para realizar a operação XOR entre dois blocos de 16 bytes
def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

# Função para realizar a substituição de bytes usando a S-Box
def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = sbox[state[i][j]]

# Função para realizar a substituição inversa de bytes usando a S-Box inversa
def inv_sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = inv_sbox[state[i][j]]

# Função para realizar o deslocamento de linhas
def shift_rows(state):
    for i in range(1, 4):
        state[i] = state[i][i:] + state[i][:i]

# Função para realizar o deslocamento inverso de linhas
def inv_shift_rows(state):
    for i in range(1, 4):
        state[i] = state[i][-i:] + state[i][:-i]

# Função para realizar a multiplicação de uma coluna por uma matriz fixa
def mix_columns(state):
    for i in range(4):
        column = [state[j][i] for j in range(4)]
        state[0][i] = mul(0x02, column[0]) ^ mul(0x03, column[1]) ^ column[2] ^ column[3]
        state[1][i] = column[0] ^ mul(0x02, column[1]) ^ mul(0x03, column[2]) ^ column[3]
        state[2][i] = column[0] ^ column[1] ^ mul(0x02, column[2]) ^ mul(0x03, column[3])
        state[3][i] = mul(0x03, column[0]) ^ column[1] ^ column[2] ^ mul(0x02, column[3])

# Função para realizar a multiplicação inversa de uma coluna por uma matriz fixa
def inv_mix_columns(state):
    for i in range(4):
        column = [state[j][i] for j in range(4)]
        state[0][i] = mul(0x0e, column[0]) ^ mul(0x0b, column[1]) ^ mul(0x0d, column[2]) ^ mul(0x09, column[3])
        state[1][i] = mul(0x09, column[0]) ^ mul(0x0e, column[1]) ^ mul(0x0b, column[2]) ^ mul(0x0d, column[3])
        state[2][i] = mul(0x0d, column[0]) ^ mul(0x09, column[1]) ^ mul(0x0e, column[2]) ^ mul(0x0b, column[3])
        state[3][i] = mul(0x0b, column[0]) ^ mul(0x0d, column[1]) ^ mul(0x09, column[2]) ^ mul(0x0e, column[3])

# Função para multiplicar dois bytes no corpo finito Galois Field (GF(2^8))
def mul(a, b):
    p = 0
    while a and b:
        if b & 1:
            p ^= a
        if a & 0x80:
            a = (a << 1) ^ 0x11b
        else:
            a <<= 1
        b >>= 1
    return p

# Função para adicionar a chave de round ao estado
def add_round_key(state, round_key):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]

# Função para expandir a chave em chaves de round
def key_expansion(key):
    expanded_key = [key[i:i+4] for i in range(0, len(key), 4)]
    for i in range(4, 4 * 11):
        temp = expanded_key[i-1].copy()
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            sub_bytes(temp)
            temp[0] ^= rcon[i // 4][0]
        expanded_key.append(xor_bytes(expanded_key[i-4], temp))
    return expanded_key

# Função para criptografar um bloco de 16 bytes usando AES
def encrypt_block(block, key):
    state = [list(block[i:i+4]) for i in range(0, len(block), 4)]

    round_keys = key_expansion(key)

    add_round_key(state, round_keys[0])

    for r in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[r])

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[10])

    return bytes(sum(state, []))

# Função para descriptografar um bloco de 16 bytes usando AES
def decrypt_block(block, key):
    state = [list(block[i:i+4]) for i in range(0, len(block), 4)]

    round_keys = key_expansion(key)

    add_round_key(state, round_keys[10])

    for r in range(9, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[r])
        inv_mix_columns(state)

    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0])

    return bytes(sum(state, []))

# Tabela S-Box
sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# Tabela S-Box inversa
inv_sbox = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

# Matriz de mistura de colunas
mix_column_matrix = [
    [0x02, 0x03, 0x01, 0x01],
    [0x01, 0x02, 0x03, 0x01],
    [0x01, 0x01, 0x02, 0x03],
    [0x03, 0x01, 0x01, 0x02]
]

# Matriz de mistura de colunas inversa
inv_mix_column_matrix = [
    [0x0e, 0x0b, 0x0d, 0x09],
    [0x09, 0x0e, 0x0b, 0x0d],
    [0x0d, 0x09, 0x0e, 0x0b],
    [0x0b, 0x0d, 0x09, 0x0e]
]

# Tabela de rodadas para a geração das chaves de round
rcon = [
    [0x00, 0x00, 0x00, 0x00],
    [0x01, 0x00, 0x00, 0x00],
    [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00],
    [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00],
    [0x80, 0x00, 0x00, 0x00],
    [0x1b, 0x00, 0x00, 0x00],
    [0x36, 0x00, 0x00, 0x00]
]

# Função para aplicar a substituição de bytes
def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = sbox[state[i][j]]

# Função para aplicar a substituição de bytes inversa
def inv_sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = inv_sbox[state[i][j]]

# Função para aplicar o deslocamento de linhas
def shift_rows(state):
    for i in range(1, 4):
        state[i] = state[i][i:] + state[i][:i]

# Função para aplicar o deslocamento de linhas inverso
def inv_shift_rows(state):
    for i in range(1, 4):
        state[i] = state[i][-i:] + state[i][:-i]

# Função para multiplicar duas colunas
def mix_columns(state, matrix):
    for i in range(4):
        column = [state[j][i] for j in range(4)]
        state[0][i] = matrix[0][0] * column[0] ^ matrix[0][1] * column[1] ^ matrix[0][2] * column[2] ^ matrix[0][3] * column[3]
        state[1][i] = matrix[1][0] * column[0] ^ matrix[1][1] * column[1] ^ matrix[1][2] * column[2] ^ matrix[1][3] * column[3]
        state[2][i] = matrix[2][0] * column[0] ^ matrix[2][1] * column[1] ^ matrix[2][2] * column[2] ^ matrix[2][3] * column[3]
        state[3][i] = matrix[3][0] * column[0] ^ matrix[3][1] * column[1] ^ matrix[3][2] * column[2] ^ matrix[3][3] * column[3]

# Função para multiplicar duas colunas inversamente
def inv_mix_columns(state, matrix):
    for i in range(4):
        column = [state[j][i] for j in range(4)]
        state[0][i] = matrix[0][0] * column[0] ^ matrix[0][1] * column[1] ^ matrix[0][2] * column[2] ^ matrix[0][3] * column[3]
        state[1][i] = matrix[1][0] * column[0] ^ matrix[1][1] * column[1] ^ matrix[1][2] * column[2] ^ matrix[1][3] * column[3]
        state[2][i] = matrix[2][0] * column[0] ^ matrix[2][1] * column[1] ^ matrix[2][2] * column[2] ^ matrix[2][3] * column[3]
        state[3][i] = matrix[3][0] * column[0] ^ matrix[3][1] * column[1] ^ matrix[3][2] * column[2] ^ matrix[3][3] * column[3]

# Função para aplicar a operação XOR entre a matriz de estado e a chave da rodada
def add_round_key(state, round_key):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]

# Função para expandir a chave em chaves de round
def expand_key(key):
    expanded_key = [row[:] for row in key]

    for i in range(4, 44):
        temp = expanded_key[i - 1][:]

        if i % 4 == 0:
            temp = [temp[1], temp[2], temp[3], temp[0]]

            for j in range(4):
                temp[j] = sbox[temp[j]]
            temp[0] ^= rcon[i // 4]

        expanded_key.append([expanded_key[i - 4][j] ^ temp[j] for j in range(4)])

    return expanded_key

# Função para criptografar a mensagem utilizando o AES
def encrypt(message, key):
    state = [[message[j][i] for j in range(4)] for i in range(4)]
    expanded_key = expand_key(key)

    add_round_key(state, expanded_key[:4])

    for i in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state, mix_column_matrix)
        add_round_key(state, expanded_key[4 * i: 4 * (i + 1)])

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, expanded_key[40:])

    return state

# Função para decryptografar a mensagem utilizando o AES
def decrypt(ciphertext, key):
    state = [[ciphertext[j][i] for j in range(4)] for i in range(4)]
    expanded_key = expand_key(key)

    add_round_key(state, expanded_key[40:])
    inv_shift_rows(state)
    inv_sub_bytes(state)

    for i in range(9, 0, -1):
        add_round_key(state, expanded_key[4 * i: 4 * (i + 1)])
        inv_mix_columns(state, inv_mix_column_matrix)
        inv_shift_rows(state)
        inv_sub_bytes(state)

    add_round_key(state, expanded_key[:4])

    return state

# Função para converter uma string em uma matriz de bytes
def convert_string_to_matrix(string):
    matrix = []
    for i in range(0, len(string), 4):
        matrix.append([ord(char) for char in string[i:i+4]])
    return matrix

# Função para converter uma matriz de bytes em uma string
def convert_matrix_to_string(matrix):
    string = ""
    for i in range(4):
        for j in range(4):
            string += chr(matrix[j][i])
    return string

# Função para exibir uma matriz de bytes em formato hexadecimal
def display_matrix(matrix):
    for i in range(4):
        for j in range(4):
            print(hex(matrix[j][i])[2:].zfill(2), end=" ")
        print()
    print()

# Obtendo a escolha do usuário
choice = input("Escolha 'c' para criptografar ou 'd' para decryptografar: ")

if choice == 'c':
    plaintext = input("Digite o texto para criptografar: ")
    key = input("Digite a chave de criptografia (16 caracteres): ")

    # Verificando se a chave tem o tamanho correto
    if len(key) != 16:
        print("A chave deve ter 16 caracteres.")
        exit()

    # Convertendo o texto e a chave para matrizes de bytes
    plaintext_matrix = convert_string_to_matrix(plaintext)
    key_matrix = convert_string_to_matrix(key)

    # Criptografando a mensagem
    ciphertext_matrix = encrypt(plaintext_matrix, key_matrix)

    # Exibindo o resultado
    print("Mensagem criptografada:")
    display_matrix(ciphertext_matrix)

elif choice == 'd':
    ciphertext = input("Digite o texto para decryptografar: ")
    key = input("Digite a chave de criptografia (16 caracteres): ")

    # Verificando se a chave tem o tamanho correto
    if len(key) != 16:
        print("A chave deve ter 16 caracteres.")
        exit()

    # Convertendo o texto e a chave para matrizes de bytes
    ciphertext_matrix = convert_string_to_matrix(ciphertext)
    key_matrix = convert_string_to_matrix(key)

    # Decryptografando a mensagem
    plaintext_matrix = decrypt(ciphertext_matrix, key_matrix)

    # Exibindo o resultado
    print("Mensagem decryptografada:")
    display_matrix(plaintext_matrix)

else:
    print("Escolha inválida.")
