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