import os
import random
import math
import hashlib
import base64

# função percorre a sequência de bits de 8 em 8 bits, 
# converte cada byte binário em um valor decimal e, em seguida, 
# converte o valor decimal em um caractere
def bits_to_string(bit_string):
    byte_list = []
    for i in range(0, len(bit_string), 8):
        byte = bit_string[i:i+8]
        decimal_value = int(byte, 2)
        character = chr(decimal_value)
        byte_list.append(character)

    message = ''.join(byte_list)
    return message

escolha = int(input("Escolha: \n1 - Cifração e decifração AES, chave 128 bits \n2 - Geração de chaves e cifra RSA \n3 - Assinatura RSA \n4 - Verificação\n"))
match escolha:
    case 1:
        # Transformação final, de uma string de bits para uma string hexadecimal
        def bits_to_hex(bit_string):
            hex_string = ''
            # Percorre a string de bits de 4 em 4 bits
            for i in range(0, len(bit_string), 4):
                # Extrai o nibble de 4 bits
                nibble = bit_string[i:i+4]
                # Converte o nibble de binário para hexadecimal
                nibble_hex = hex(int(nibble, 2))[2:]
                # Adiciona o nibble hexadecimal à string de hexadecimais
                hex_string += nibble_hex

            return hex_string


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
            message = input("Digite a mensagem a ser cifrada: ")
            key = input("Digite a chave AES de 128 bits(16 caracteres): ")

            def message_to_bits(message):
                bit_string = ''
                for char in message:
                    decimal_value = ord(char)
                    binary_value = bin(decimal_value)[2:].zfill(8)
                    bit_string += binary_value

                return bit_string

            # Chave em bits
            bit_sequence_key = ""
            for byte_sequence in key.encode('utf-8'):
                bit_sequence_key += f'{byte_sequence:08b}'

            # Completando a mensagem com os espaços faltantes para 16 bytes
            if (len(message)-1) % 16 != 0:
                message = message + (((16 - len(message)) % 16) * " ")
            
            # Completando a chave com os espaços faltantes para 16 bytes
            if (len(key)-1) % 16 != 0:
                key = key + (((16 - len(key)) % 16) * " ")

            # Função que transforma a mensagem e a chave em blocos 4x4
            def create_matriz(message):
                matriz = [[0 for _ in range(4)] for _ in range(4)]

                # Preenchimento da matriz com os valores da mensagem em bits
                for i in range(4):
                    for j in range(4):
                        matriz[i][j] = message[0:8]
                        message = message[8:]
                return matriz

            matriz_key = create_matriz(bit_sequence_key)

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
            
            
            # Variavel que recebe a mensagem criptografada
            message_cripted = ""
            # SEPARA A MENSAGEM EM BLOCOS DE 16 BYTES E CRIPTOGRAFA TODOS ELES
            for block in range(0, len(message), 16):
                bit_sequence_message = ""
                # Mensagem em bits
                for byte_sequence in message[block:block+16].encode('utf-8'):
                    bit_sequence_message += f'{byte_sequence:08b}'
                matriz_message = create_matriz(bit_sequence_message)

                
                # PRIMEIRA RODADA APENAS ADD A CHAVE
                #INCLUI A CHAVE DE RODADA
                matriz_message = add_round_key(matriz_message, keys[1])
                

                # 9 RODADAS DE MALUCO
                for i in range(8):
                    # SUBSTITUÇÃO DE BYTES
                    matriz_message = sub_bytes(matriz_message, s_box)
                    
                    # DESLOCAMENTO DE LINHAS
                    matriz_message = shift_rows(matriz_message)
                    
                    # EMBARALHAMENTO DE COLUNAS
                    matriz_message = mix_columns(matriz_message)
                    
                    # INCLUI A CHAVE DE RODADA
                    matriz_message = add_round_key(matriz_message, keys[i+2])
                    

                #10° RODADA DE MALUCO
                # SUBSTITUÇÃO DE BYTES
                matriz_message = sub_bytes(matriz_message, s_box)
                
                # DESLOCAMENTO DE LINHAS
                matriz_message = shift_rows(matriz_message)
                
                # INCLUI A CHAVE DE RODADA
                matriz_message = add_round_key(matriz_message, keys[10])


                for line in matriz_message:
                    for caracter in line:
                        message_cripted += caracter
                
            #CONVERTER BITS EM STRING NORMAL
            message_cripted = bits_to_hex(message_cripted)

            print(f'Mensagem criptografada: {message_cripted}')


#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

        if escolha_AES == 3:
            # Recebe a mensagem criptografada e a chave para a decifração AES
            message_cripted = input("Digite a mensagem criptografada: ")
            key = input("Digite a chave AES de 128 bits(16 caracteres): ")

            # Chave em bits
            bit_sequence_key = ""
            for byte_sequence in key.encode('utf-8'):
                bit_sequence_key += f'{byte_sequence:08b}'

            # Função que transforma a mensagem criptografada em blocos 4x4
            def create_matriz(message):
                matriz = [[0 for _ in range(4)] for _ in range(4)]

                # Preenchimento da matriz com os valores da mensagem em bits
                for i in range(4):
                    for j in range(4):
                        matriz[i][j] = message[0:8]
                        message = message[8:]
                return matriz

            matriz_key = create_matriz(bit_sequence_key)

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

            # FUNÇÃO AUXILIAR PARA mix_columns
            def mix_column(column):
                mixed_column = []
                for i in range(4):
                    mixed_column.append(galois_multiply(column[0], 0x0E) ^
                                        galois_multiply(column[1], 0x0B) ^
                                        galois_multiply(column[2], 0x0D) ^
                                        galois_multiply(column[3], 0x09))
                    column = column[1:] + [column[0]]  # Shift para a esquerda

                return mixed_column

            # FUNÇÃO PARA DESFAZER A MISTURA DAS COLUNAS
            def inv_mix_columns(state):
                inv_mix_matrix = [
                    [0x0E, 0x0B, 0x0D, 0x09],
                    [0x09, 0x0E, 0x0B, 0x0D],
                    [0x0D, 0x09, 0x0E, 0x0B],
                    [0x0B, 0x0D, 0x09, 0x0E]
                ]

                for j in range(4):
                    column = [int(state[i][j], 2) for i in range(4)]
                    mixed_column = inv_mix_column(column)
                    for i in range(4):
                        state[i][j] = format(mixed_column[i], '08b')  # Convertendo de volta para string binária

                return state

            # FUNÇÃO AUXILIAR PARA inv_mix_columns
            def inv_mix_column(column):
                mixed_column = []
                for i in range(4):
                    mixed_column.append(galois_multiply(column[0], 0x0E) ^
                                        galois_multiply(column[1], 0x0B) ^
                                        galois_multiply(column[2], 0x0D) ^
                                        galois_multiply(column[3], 0x09))
                    column = column[1:] + [column[0]]  # Shift para a esquerda

                return mixed_column

            # FUNÇÃO INVERSA DE SUBSTITUIÇÃO DE BYTES
            def inv_sub_bytes(state, inv_s_box):
                for i in range(4):
                    for j in range(4):
                        byte = state[i][j]
                        row = int(byte[:4], 2)
                        col = int(byte[4:], 2)
                        substituted_byte = inv_s_box[row * 16 + col]
                        state[i][j] = f'{substituted_byte:08b}'

                return state

            # FUNÇÃO INVERSA DE DESLOCAMENTO DE LINHAS
            def inv_shift_rows(state):
                # Deslocamento da segunda linha em 1 posição para a direita
                state[1] = [state[1][3]] + state[1][:3]

                # Deslocamento da terceira linha em 2 posições para a direita
                state[2] = state[2][2:] + state[2][:2]

                # Deslocamento da quarta linha em 3 posições para a direita
                state[3] = state[3][1:] + [state[3][0]]

                return state

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

            # FUNÇÃO SUBSTITUIÇÃO DE BYTES APENAS PARA A FUNÇAO QUE FAZ AS SUBCHAVES
            def sub_bytes(state, s_box):
                for i in range(4):
                    for j in range(4):
                        byte = state[i][j]
                        row = int(byte[:4], 2)
                        col = int(byte[4:], 2)
                        substituted_byte = s_box[row * 16 + col]
                        state[i][j] = f'{substituted_byte:08b}'

                return state

            # FUNÇÃO QUE DESFAZ A ADIÇÃO DA CHAVE DE RODADA
            def inv_add_round_key(state, key):
                for i in range(4):
                    for j in range(4):
                        state[i][j] = format(int(state[i][j], 2) ^ int(key[i][j], 2), '08b')

                return state

            keys = key_expansion(matriz_key, s_box)

            # Variável que recebe a mensagem descriptografada
            message_decrypted = ""

            # SEPARA A MENSAGEM CRIPTOGRAFADA EM BLOCOS DE 16 BYTES E DECRIPTOGRAFA TODOS ELES
            for block in range(0, len(message_cripted), 32):
                bit_sequence_message = ""
                # Mensagem criptografada em bits
                for i in range(block, block + 32, 2):
                    byte = message_cripted[i:i+2]
                    bit_sequence_message += f'{int(byte, 16):08b}'
                matriz_message = create_matriz(bit_sequence_message)

                
                # 10° RODADA DE MALUCO (INVERSA)
                # INCLUI A CHAVE DE RODADA
                matriz_message = inv_add_round_key(matriz_message, keys[10])
                
                # DESLOCAMENTO DE LINHAS (INVERSO)
                matriz_message = inv_shift_rows(matriz_message)
                
                # INVERSA DE SUBSTITUIÇÃO DE BYTES
                matriz_message = inv_sub_bytes(matriz_message, inv_s_box)
                

                # 9 RODADAS DE MALUCO (INVERSA)
                for i in range(8, 0, -1):
                    # INCLUI A CHAVE DE RODADA
                    matriz_message = inv_add_round_key(matriz_message, keys[i+1])
                    
                    # INVERSA DE EMBARALHAMENTO DE COLUNAS
                    matriz_message = inv_mix_columns(matriz_message)
                    
                    # DESLOCAMENTO DE LINHAS (INVERSO)
                    matriz_message = inv_shift_rows(matriz_message)
                    
                    # INVERSA DE SUBSTITUIÇÃO DE BYTES
                    matriz_message = inv_sub_bytes(matriz_message, inv_s_box)
                    

                # PRIMEIRA RODADA APENAS REMOVE A CHAVE
                # INCLUI A CHAVE DE RODADA
                matriz_message = inv_add_round_key(matriz_message, keys[1])


                for line in matriz_message:
                    for character in line:
                        message_decrypted += character
            # CONVERTER BITS EM STRING NORMAL
            message_decrypted = bits_to_string(message_decrypted)

            print(f'Mensagem descriptografada: {message_decrypted}')

    case 2:

        def extended_gcd(a, b):
            """Calcula o MDC estendido entre dois números."""
            if a == 0:
                return b, 0, 1
            else:
                g, y, x = extended_gcd(b % a, a)
                return g, x - (b // a) * y, y


        def mod_inverse(a, m):
            """Calcula o inverso multiplicativo de 'a' módulo 'm'."""
            g, x, _ = extended_gcd(a, m)
            if g == 1:
                return x % m


        def generate_keys(key_size):
            """Gera as chaves pública e privada RSA utilizando OAEP."""
            # Gerar dois primos grandes e distintos
            p = generate_prime(key_size // 2)
            q = generate_prime(key_size // 2)
            n = p * q
            # Totiente de Euler
            phi_n = (p - 1) * (q - 1)

            # Encontrar um expoente de criptografia e seu inverso multiplicativo módulo phi(n)
            e = random.randint(2, phi_n - 1)
            while True:
                if math.gcd(e, phi_n) == 1:
                    break
                e = random.randint(2, phi_n - 1)
            d = mod_inverse(e, phi_n)

            # Chave pública: (n, e)
            # Chave privada: (n, d)
            return (n, e), (n, d)


        def generate_prime(bit_length):
            """Gera um número primo aleatório com a quantidade de bits especificada."""
            while True:
                num = random.getrandbits(bit_length)
                num |= (1 << bit_length - 1) | 1  # Define o bit mais significativo e o bit menos significativo como 1
                if is_prime(num):
                    return num


        def is_prime(n, k=40):
            """Realiza o teste de Miller-Rabin para verificar a primalidade de um número."""
            if n <= 1:
                return False
            if n <= 3:
                return True
            if n % 2 == 0:
                return False

            r, s = 0, n - 1
            while s % 2 == 0:
                r += 1
                s //= 2

            for _ in range(k):
                a = random.randint(2, n - 2)
                x = pow(a, s, n)
                if x == 1 or x == n - 1:
                    continue

                for _ in range(r - 1):
                    x = pow(x, 2, n)
                    if x == n - 1:
                        break
                else:
                    return False

            return True


        def pad(message, block_size):
            # Tamanho do hash
            hash_size = 224

            # Tamanho do espaço aleatório
            random_size = (block_size - len(message) - 2) * (hash_size - 2)

            # Gerar sequência aleatória
            r = random.getrandbits(random_size)
            r_bytes = r.to_bytes((random_size + 7) // 8, "big")

            # Codificar a mensagem
            message_encoded = message.encode("utf-8")  # Use a codificação apropriada para a mensagem

            '''
            print(message_encoded)
            print(f'mensagem encoded digest {hashlib.sha3_224(message_encoded).digest()}')
            print(f'r_bytes digest {hashlib.sha3_224(r_bytes).digest()}')
            '''

            # Gerar hashes
            hash1 = hashlib.sha3_224(message_encoded).digest()
            hash2 = hashlib.sha3_224(r_bytes).digest()

            # Realizar preenchimento
            padded_message = b"\x00" * ((block_size - len(message) - 2) - 2 * hash_size // 8) + b"\x01" + hash1 + hash2 + r_bytes

            return padded_message


        '''
        def unpad(padded_message, block_size):
            """Remove o preenchimento OAEP do bloco de mensagem."""
            # Tamanho do hash
            hash_size = 224
            
            
            # Verificar se o bloco é válido
            print(len(padded_message))
            print(block_size)
            if len(padded_message) != block_size:
                raise ValueError("Bloco de mensagem inválido")
            

            # Encontrar posição do byte de valor 1
            index = padded_message.find(b"\x01")
            if index == -1:
                raise ValueError("Byte de preenchimento inválido")

            # Separar as partes do bloco
            hash1 = padded_message[index + 1:index + 1 + hash_size]
            hash2 = padded_message[index + 1 + hash_size:index + 1 + 2 * hash_size]
            r_bytes = padded_message[index + 1 + 2 * hash_size:]

            
            # Verificar as hashes
            if hashlib.sha3_224(padded_message[:index]).digest() != hash1:
                raise ValueError("Hash inválida")
            if hashlib.sha3_224(r_bytes).digest() != hash2:
                raise ValueError("Hash inválida")
            

            # Remover o preenchimento
            message = r_bytes.strip(b"\x00")

            return message.decode("utf-8")
        '''
        
        def unpad(padded_message, block_size):
            # Tamanho do hash
            hash_size = 224

            # Verificar o preenchimento OAEP
            padded_length = block_size - hash_size // 8 - 2
            separator = padded_message[:padded_length].rindex(b"\x01")
            message_start = separator + 1
            message_end = len(padded_message)
            message = padded_message[message_start:message_end]

            return message.decode("utf-8")


        def encrypt(message, public_key):
            """Criptografa a mensagem usando a chave pública RSA com OAEP."""
            n, e = public_key
            block_size = (n.bit_length() + 7) // 8  # Correção para cálculo do tamanho do bloco

            # Realizar o preenchimento OAEP
            padded_message = pad(message, block_size)

            # Dividir a mensagem em blocos do tamanho adequado
            blocks = [padded_message[i:i + block_size] for i in range(0, len(padded_message), block_size)]

            # Criptografar cada bloco
            encrypted_blocks = []
            for block in blocks:
                m = int.from_bytes(block, "big")
                c = pow(m, e, n)
                encrypted_blocks.append(c.to_bytes(block_size, "big"))

            # Concatenar os blocos criptografados
            encrypted_message = b"".join(encrypted_blocks)

            return encrypted_message


        def decrypt(encrypted_message, private_key):
            """Descriptografa a mensagem usando a chave privada RSA com OAEP."""
            n, d = private_key
            block_size = (n.bit_length() + 7) // 8  # Correção para cálculo do tamanho do bloco

            # Dividir a mensagem criptografada em blocos do tamanho adequado
            encrypted_blocks = [encrypted_message[i:i + block_size] for i in range(0, len(encrypted_message), block_size)]

            # Descriptografar cada bloco
            decrypted_blocks = []
            for block in encrypted_blocks:
                c = int.from_bytes(block, "big")
                m = pow(c, d, n)
                decrypted_blocks.append(m.to_bytes(block_size, "big"))

            # Concatenar os blocos descriptografados
            decrypted_message = b"".join(decrypted_blocks)

            # Remover o preenchimento OAEP
            message = unpad(decrypted_message, block_size)

            return message

        
        "1 - Geração de chaves (p e q primos com no mínimo de 1024 bits) \n2 - OAEP \n3 - Cifração/decifração assimétrica RSA usando OAEP \n"
        escolha_RSA = int(input("\n1 - Geração de chaves (p e q primos com no mínimo de 1024 bits) \n2 - Cifração RSA usando OAEP\n3 - Decifração RSA usando OAEP \n"))
        
        if escolha_RSA == 1:
            print()

            # Exemplo de uso:
            public_key, private_key = generate_keys(1024)
            # Chave pública: (n, e)
            # Chave privada: (n, d)
            print("Chave pública:", public_key)
            print("Chave privada:", private_key)

        if escolha_RSA == 2:
            print()
            # Recebe a mensagem e a chave para a cifra RSA
            message = input("Digite a mensagem a ser cifrada: ")
            public_key = input("Digite a chave publica RSA 'n, e': ").strip().split(',')
            public_key = (int(public_key[0]), int(public_key[1]))

            # Criptografar a mensagem com a chave pública
            encrypted_message = encrypt(message, public_key)
            print(encrypted_message)
            encrypted_message = base64.b64encode(encrypted_message).decode()
            
            print("Mensagem criptografada:", encrypted_message)
            


        if escolha_RSA == 3:
            print()
            '''
            # Recebe a mensagem criptografada em base64 e a chave privada RSA
            encrypted_message_base64 = input("Digite a mensagem criptografada em base64: ")
            private_key = input("Digite a chave privada RSA 'n, d': ").strip().split(',')
            private_key = (int(private_key[0]), int(private_key[1]))

            # Decodifica a mensagem criptografada de base64
            encrypted_message = base64.b64decode(encrypted_message_base64)

            # Descriptografa a mensagem com a chave privada
            decrypted_message = decrypt(encrypted_message, private_key)

            print("Mensagem descriptografada:", decrypted_message)
            '''
            # Recebe a mensagem criptografada e a chave para a decifração RSA
            message = input("Digite a mensagem a ser descifratada: ")
            private_key = input("Digite a chave privada RSA 'n, d': ").strip().split(',')
            private_key = (int(private_key[0]), int(private_key[1]))

            message = base64.b64decode(message)

            # Descriptografar a mensagem com a chave privada
            decrypted_message = decrypt(message, private_key)
            print("Mensagem descriptografada:", decrypted_message)

    case 3:
        print("ola mundo3")
    case 4:
        print("ola mundo4")