# CifraAES e RSA Unb
Projeto Final para a disciplina Segurança computacional.

Nesse projeto, temos um código para o funcionamento das cifras AES e RSA

# Como rodar
Clone o repositorio usando o comando
```bash
git clone https://github.com/LuscasOSilva/CifraRSA.git
```
3. Execute o comando python CifradorEDecifrador.py no terminal.
```bash
python Cifrador&Decifrador.py
```

# Funções

Ao rodar o código, teremos as seguintes funções:

- Geração de chave 128 bits AES
- Cifração AES
- Decifração AES

- Geração de chaves (p e q primos com no mínimo de 1024 bits) primalidade Miller-Rabin
- Cifração RSA
- Decifração RSA
(Utilizando OAEP)

Além de possibilidade de assinar e verificar assinatura has em um documento.

# AES
A chave AES é gerada de forma simples, com a biblioteca "secrets" para gerar aleatoriamente a chave que retorna uma sequencia de caracteres hexademais, que são tranformados em uma sequencia de 16 bytes na base 64.

Para a cifração, temos as seguintes funções principais: 

add_round_key(usa a sub chave para alterar a mensagem)
shift_rows(deslocamento de linhas da matriz)
sub_bytes(substituição de bytes utilizando a S-box)
mix_columns(embaralhamento de colunas)
key_expansion(usada para gerar todas as sub_chaves das rodadas)

Que são usadas na sequência pedida em 11 rodadas contando com a rodada zero.

Para a decifração temos as funções que fazem o processo inverso a esse, além da utilização da key_expansion novamente.

# RSA

Para o RSA temos um processo um pouco mais forte de geração de chave, temos as seguintes funções:

is_prime = Verifica se um número n é primo usando o teste de Miller-Rabin 7 vezes
generate_prime = Gera um número primo aleatório com o número especificado de bits, 1024 sempre
extended_gcd = Calcula o máximo divisor comum (MDC) e os coeficientes de Bézout do algoritmo de Euclides estendido
mod_inverse = Calcula o inverso multiplicativo modular de a (mod m)
generate_keypair = Gera um par de chaves RSA usando o tamanho de chave especificado e as funções anteriores, retornando (n, e), (n, d)
O pedaço do codigo a seguir, public_key, private_key = generate_keypair(1024) coleta as chaves publicas e privadas

A cifração é feita com as seguintes funções:

pad_message = Realiza a padronização OEAP da mensagem
rsa_encrypt = Chama a função pad_message para o OAEP e cifra a mensagem usando a chave pública RSA
unpad_message = Remove o padding OEAP da mensagem
rsa_decrypt = Decifra o texto cifrado usando a chave privada RSA e retira a padronização OEAP com a unpad_message