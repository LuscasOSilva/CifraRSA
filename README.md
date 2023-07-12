# Cifra AES e RSA UnB
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

- Geração de chaves RSA (p e q primos com no mínimo de 1024 bits) primalidade Miller-Rabin
- Cifração RSA
- Decifração RSA
- Assinatura RSA
- Verificação de assinatura RSA
(Utilizando OAEP)

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

# Assinatura RSA

A assinatura é feita baseada em uma mensagem que deve ser assinada, usando a biblioteca de hash (hashlib) com a chave privada e a função de Encriptação RSA

A verificação é feita apenas fazendo a decriptação da mensagem com a assinatura e comparando com a mensagem original

# Fontes

https://www.nist.gov/publications/advanced-encryption-standard-aes
https://www.youtube.com/watch?v=-lybDqNi-bM&t=1410s&ab_channel=DanielVecchiato
https://www.youtube.com/watch?v=GAR1Ur_2IGk&ab_channel=F%C3%A1bricadeNoobs
https://www.youtube.com/watch?v=-lybDqNi-bM&ab_channel=DanielVecchiato
https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding