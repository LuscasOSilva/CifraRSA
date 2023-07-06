import os
'''
#CONVERTER BITS EM STRING NORMAL
byte_sequence = int(bit_sequence_mesage, 2).to_bytes((len(bit_sequence_mesage) + 7) // 8, 'big')
string = byte_sequence.decode('utf-8')

'''

escolha = int(input("Escolha: \n1 - Cifração e decifração AES, chave 128 bits \n2 - Geração de chaves e cifra RSA \n3 - Assinatura RSA \n4 - Verificação\n"))
match escolha:
    case 1:

        # S-Box do AES
        s_box = [
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
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
        ]

        # S-Box inversa do AES
        inv_s_box = [
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
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
        ]
        escolha_AES = int(input("Digite: \n1 - Geração de chave de 128 bits \n2 - Cifração \n3 - Decifração\n"))
        if escolha_AES == 1:
            print()
        if escolha_AES == 2:
            # Recebe a mensagem e a chave para a cifra AES
            mesage = input("Digite a mensagem a ser cifrada: ")
            key = input("Digite a chave AES de 128 bits(16 caracteres): ")

            # Chave em bits
            bit_sequence_key = ""
            for byte_sequence in key.encode('utf-8'):
                bit_sequence_key += f'{byte_sequence:08b}'

            # Completando a mensagem com os espaços faltantes para 16 bytes
            if (len(mesage)-1) % 16 != 0:
                mesage = mesage + (((16 - len(mesage)) % 16) * " ")
            
            def cria_matriz(mesage):
                matriz = [[0 for _ in range(4)] for _ in range(4)]

                # Preenchimento da matriz com os valores da mensagem em bits
                for i in range(4):
                    for j in range(4):
                        matriz[i][j] = mesage[0:8]
                        mesage = mesage[8:]
                return matriz

            matriz_key = cria_matriz(bit_sequence_key)

            # FUNÇÃO PARA DESLOCAR AS LINHAS ASSIM COMO PEDIDO NO ALGORITMO AES
            def shift_rows(state):
                # Deslocamento da segunda linha em 1 posição para a esquerda
                state[1] = state[1][1:] + state[1][:1]

                # Deslocamento da terceira linha em 2 posições para a esquerda
                state[2] = state[2][2:] + state[2][:2]

                # Deslocamento da quarta linha em 3 posições para a esquerda
                state[3] = state[3][3:] + state[3][:3]

                return state

            # FUNÇÃO SUBSTITUIÇÃO DE BYTES ASSIM COMO PEDIDO NO ALGORITMO AES
            def sub_bytes(state, s_box):
                for i in range(4):
                    for j in range(4):
                        byte = state[i][j]
                        row = int(byte[:4], 2)
                        col = int(byte[4:], 2)
                        substituted_byte = s_box[row * 16 + col]
                        state[i][j] = f'{substituted_byte:08b}'

                return state
            
            # FUNÇÃO PARA MISTURAR COLUNAS ASSIM COMO PEDIDO NO ALGORITMO AES
            def mix_columns(state):
                mix_matrix = [
                    [0x02, 0x03, 0x01, 0x01],
                    [0x01, 0x02, 0x03, 0x01],
                    [0x01, 0x01, 0x02, 0x03],
                    [0x03, 0x01, 0x01, 0x02]
                ]

                for j in range(4):
                    column = [int(state[i][j], 2) for i in range(4)]
                    mixed_column = mix_column(column)
                    for i in range(4):
                        state[i][j] = format(mixed_column[i], '08b')  # Convertendo de volta para string binária

                return state

            # FUNÇÃO AUXILIAR PARA mix_columns
            def mix_column(column):
                mixed_column = []
                for i in range(4):
                    mixed_column.append(galois_multiply(column[0], 0x02) ^
                                        galois_multiply(column[1], 0x03) ^
                                        galois_multiply(column[2], 0x01) ^
                                        galois_multiply(column[3], 0x01))
                    column = column[1:] + [column[0]]  # Shift para a esquerda

                return mixed_column

            # FUNÇÃO AUXILIAR PARA mix_columns utilizando a multiplicação de Galois
            def galois_multiply(a, b):
                p = 0
                for i in range(8):
                    if b & 1:
                        p ^= a
                    carry = a & 0x80  # Bit mais significativo
                    a = (a << 1) & 0xFF
                    if carry:
                        a ^= 0x1B  # Valor fixo do AES
                    b >>= 1

                return p

            
            #FUNÇÃO QUE DEFINE AS SUBCHAVES DE EXPANÇÃO PARA CADA RODADA DO AES
            def key_expansion(key, s_box):
                round_constants = ['00000001', 
                                    '00000010', 
                                    '00000100', 
                                    '00001000', 
                                    '00010000', 
                                    '00100000', 
                                    '01000000', 
                                    '10000000', 
                                    '00011011', 
                                    '00110110']
                expanded_key = [key]

                # Realiza a expansão da chave
                for i in range(10):
                    prev_key = expanded_key[-1]
                    new_key = []

                    # Rotação da coluna
                    temp = prev_key[1:] + [prev_key[0]]
                    

                    # Substituição pelos valores da S-Box
                    new_key = sub_bytes(temp, s_box)

                    # Aplica XOR com o round constant
                    round_constant = round_constants[i]
                    new_key[0][0] = format(int(new_key[0][0], 2) ^ int(round_constant, 2), '08b')

                    # Aplica XOR com a palavra anterior da chave
                    for i in range(4):
                        for j in range(4):
                            new_key[i][j] = format(int(new_key[i][j], 2) ^ int(prev_key[i][j], 2), '08b')

                    expanded_key.append(new_key)

                return expanded_key


            # FUNÇÃO QUE ADICIONA A CHAVE DE RODADA ASSIM COMO PEDIDO NO ALGORITMO AES
            def add_round_key(state, key):
                for i in range(4):
                    for j in range(4):
                        state[i][j] = format(int(state[i][j], 2) ^ int(key[i][j], 2), '08b')

                return state


            keys = key_expansion(matriz_key, s_box)

            print(keys)
                
            # SEPARA A MENSAGEM EM BLOCOS DE 16 BYTES E CRIPTOGRAFA TODOS ELES
            for block in range(0, len(mesage), 16):
                bit_sequence_mesage = ""
                # Mensagem em bits
                for byte_sequence in mesage[block:block+16].encode('utf-8'):
                    bit_sequence_mesage += f'{byte_sequence:08b}'
                matriz_mesage = cria_matriz(bit_sequence_mesage)

                # PRIMEIRA RODADA APENAS ADD A CHAVE
                #INCLUI A CHAVE DE RODADA

                # 9 RODADAS DE MALUCO
                for i in range(9):
                    # SUBSTITUÇÃO DE BYTES
                    matriz_mesage = sub_bytes(matriz_mesage, s_box)
                    # DESLOCAMENTO DE LINHAS
                    matriz_mesage = shift_rows(matriz_mesage)
                    # EMBARALHAMENTO DE COLUNAS
                    matriz_mesage = mix_columns(matriz_mesage)
                    # INCLUI A CHAVE DE RODADA


                #10° RODADA DE MALUCO
                # SUBSTITUÇÃO DE BYTES
                matriz_mesage = sub_bytes(matriz_mesage, s_box)
                # DESLOCAMENTO DE LINHAS
                matriz_mesage = shift_rows(matriz_mesage)
                # INCLUI A CHAVE DE RODADA
                matriz_mesage = add_round_key(matriz_mesage, matriz_key)




        if escolha_AES == 3:
            print()
        '''
        def sub_bytes(state):
            for i in range(4):
                for j in range(4):
                    state[i][j] = s_box[state[i][j]]

        def inv_sub_bytes(state):
            for i in range(4):
                for j in range(4):
                    state[i][j] = inv_s_box[state[i][j]]

        # Função para adicionar a chave de round ao estado
        def add_round_key(state, round_key):
            for i in range(4):
                for j in range(4):
                    state[i][j] ^= round_key[i][j]

        def encrypt(plaintext, key):
            # Converter a chave em uma matriz 4x4
            round_key = key_schedule(key)

            # Converter o texto plano em uma matriz 4x4
            state = [[0] * 4 for _ in range(4)]
            for i in range(4):
                for j in range(4):
                    state[j][i] = plaintext[i * 4 + j]

            # Adicionar a chave inicial ao estado
            add_round_key(state, round_key[0])

            # Executar as 10 rodadas do algoritmo AES
            for r in range(1, 11):
                sub_bytes(state)
                shift_rows(state)
                if r != 10:
                    mix_columns(state)
                add_round_key(state, round_key[r])

            # Converter o estado criptografado de volta para um vetor
            ciphertext = []
            for i in range(4):
                for j in range(4):
                    ciphertext.append(state[j][i])

            return ciphertext

        def decrypt(ciphertext, key):
            # Converter a chave em uma matriz 4x4
            round_key = key_schedule(key)

            # Converter o texto cifrado em uma matriz 4x4
            state = [[0] * 4 for _ in range(4)]
            for i in range(4):
                for j in range(4):
                    state[j][i] = ciphertext[i * 4 + j]

            # Adicionar a chave de round final ao estado
            add_round_key(state, round_key[10])

            # Executar as 10 rodadas inversas do algoritmo AES
            for r in range(9, 0, -1):
                inv_shift_rows(state)
                inv_sub_bytes(state)
                add_round_key(state, round_key[r])
                if r != 1:
                    inv_mix_columns(state)

            # Converter o estado descriptografado de volta para um vetor
            plaintext = []
            for i in range(4):
                for j in range(4):
                    plaintext.append(state[j][i])

            return plaintext

        # Função para agendar as chaves de round
        def key_schedule(key):
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
            round_keys = [[]] * 11
            round_keys[0] = key

            for r in range(1, 11):
                temp = [0] * 4
                for i in range(4):
                    temp[i] = round_keys[r - 1][(i - 1) % 4]

                if r % 4 == 0:
                    temp = sub_word(rot_word(temp))
                    for i in range(4):
                        temp[i] ^= rcon[r // 4][i]

                round_keys[r] = []
                for i in range(4):
                    round_keys[r].append(round_keys[r - 1][i] ^ temp[i])

            return round_keys

        # Função para rotacionar uma palavra de 4 bytes
        def rot_word(word):
            return word[1:] + word[:1]

        # Função para substituir cada byte de uma palavra de 4 bytes usando a S-Box
        def sub_word(word):
            for i in range(4):
                word[i] = s_box[word[i]]
            return word

        # Função para deslocar as linhas da matriz de estado
        def shift_rows(state):
            for i in range(1, 4):
                state[i] = state[i][i:] + state[i][:i]

        def inv_shift_rows(state):
            for i in range(1, 4):
                state[i] = state[i][-i:] + state[i][:-i]

        # Função para misturar as colunas da matriz de estado
        def mix_columns(state):
            for i in range(4):
                column = [state[j][i] for j in range(4)]
                state[0][i] = mul(0x02, column[0]) ^ mul(0x03, column[1]) ^ column[2] ^ column[3]
                state[1][i] = column[0] ^ mul(0x02, column[1]) ^ mul(0x03, column[2]) ^ column[3]
                state[2][i] = column[0] ^ column[1] ^ mul(0x02, column[2]) ^ mul(0x03, column[3])
                state[3][i] = mul(0x03, column[0]) ^ column[1] ^ column[2] ^ mul(0x02, column[3])

        def inv_mix_columns(state):
            for i in range(4):
                column = [state[j][i] for j in range(4)]
                state[0][i] = mul(0x0e, column[0]) ^ mul(0x0b, column[1]) ^ mul(0x0d, column[2]) ^ mul(0x09, column[3])
                state[1][i] = mul(0x09, column[0]) ^ mul(0x0e, column[1]) ^ mul(0x0b, column[2]) ^ mul(0x0d, column[3])
                state[2][i] = mul(0x0d, column[0]) ^ mul(0x09, column[1]) ^ mul(0x0e, column[2]) ^ mul(0x0b, column[3])
                state[3][i] = mul(0x0b, column[0]) ^ mul(0x0d, column[1]) ^ mul(0x09, column[2]) ^ mul(0x0e, column[3])

        # Função para multiplicar dois bytes no corpo de Galois
        def mul(a, b):
            result = 0
            while b:
                if b & 0x01:
                    result ^= a
                if a & 0x80:
                    a = (a << 1) ^ 0x1b
                else:
                    a <<= 1
                b >>= 1
            return result

        # Teste
        plaintext = [0x32, 0x88, 0x31, 0xe0, 0x43, 0x5a, 0x31, 0x37, 0xf6, 0x30, 0x98, 0x07, 0xa8, 0x8d, 0xa2, 0x34]
        key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]

        ciphertext = encrypt(plaintext, key)
        decrypted_plaintext = decrypt(ciphertext, key)

        print("Texto Cifrado: ", ciphertext)
        print("Texto Descriptografado: ", decrypted_plaintext)
        '''
    case 2:
        print("ola mundo2")
    case 3:
        print("ola mundo3")
    case 4:
        print("ola mundo4")