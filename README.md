# CriptoBitwise

Criptografador em JavaScript puro que combina **obfuscação**, **operadores bitwise**, **Cipher Block Chaining (CBC)** e um gerador de números pseudoaleatórios baseado em **Xorshift128** para proteger mensagens.

O objetivo deste projeto é ser um estudo de caso sobre como combinar várias técnicas criptográficas (não apenas um único algoritmo) para dificultar ataques comuns. **Não é recomendado para uso em produção** sem uma revisão por especialistas em criptografia.

---

## Índice

- [Visão geral do fluxo](#visão-geral-do-fluxo)
- [Arquitetura](#arquitetura)
  - [xorshift128 — PRNG](#xorshift128--prng)
  - [FNV-1a com Key Stretching (gerarNumero)](#fnv-1a-com-key-stretching-gerarnumero)
  - [gerarHash — derivação de chave](#gerarhash--derivação-de-chave)
  - [Vetor de Inicialização (IV)](#vetor-de-inicialização-iv)
- [Etapas da criptografia](#etapas-da-criptografia)
  - [1. Criptografia por bloco com CBC (criptR)](#1-criptografia-por-bloco-com-cbc-criptr)
  - [2. Obfuscação por inserção de lixo (criptT)](#2-obfuscação-por-inserção-de-lixo-criptt)
  - [3. Codificação final (criptTrashToString)](#3-codificação-final-cripttrashtostring)
  - [4. Código de Autenticação de Mensagem — MAC (gerarMAC)](#4-código-de-autenticação-de-mensagem--mac-gerarmac)
- [Etapas da descriptografia](#etapas-da-descriptografia)
- [Formato da mensagem final](#formato-da-mensagem-final)
- [Ataques que o projeto tenta mitigar](#ataques-que-o-projeto-tenta-mitigar)
- [Como usar](#como-usar)
- [Referências](#referências)

---

## Visão geral do fluxo

```
CRIPTOGRAFIA
──────────────────────────────────────────────────────────────────────────
[ Mensagem ]              [ Chave ]
     │                        │
     │                        ▼
     │            gerarInitializationVector()
     │                        │
     │                        ▼
     └──────────────► gerarHash(Chave + IV)
                     (FNV-1a / 100k iterações)
                              │
                              ▼
                   startXorGenerators(IV)
         ┌───────────────┬───────────────┬───────────────┐
         ▼               ▼               ▼               ▼
  xor128Trashing  xor128Rotation   xor128Size     xor128Numbers
   (fatia 0-64)    (fatia 64-96)  (128-192)      (192-256)
         │               │               │               │
         │               ▼               │               │
         │      1. criptR()              │               │
         │      (CBC + Rotação + XOR)    │               │
         │               │               │               │
         └───────────────┼───────────────┴───────────────┤
                         ▼                               │
                2. criptT() ◄────────────────────────────┘
                (Obfuscação por Lixo)
                         │
                         ▼
                3. criptTrashToString() ───► [ Cifra Hex ]
                                                    │
                                                    ▼
    [ Chave ] ─────────────────────────────► 4. gerarMAC()
                                                    │
                                                    ▼
                                              [ MAC (32 hex) ]

 ┌──────────────────────────────────────────────────────────────┐
 │ RESULTADO FINAL: <cifra_hex>-<mac_32_hex>-<iv_48_hex>        │
 └──────────────────────────────────────────────────────────────┘
```

A descriptografia percorre o caminho inverso: primeiro verifica o MAC (em tempo constante) e, **somente se válido**, remove o lixo, reverte o CBC e recupera a mensagem.

---

## Arquitetura

### xorshift128 — PRNG

Gerador de números pseudoaleatórios baseado no clássico **Xorshift128** (Marsaglia, 2003), porém **modificado** para resistir a ataques de álgebra linear.

O Xorshift original é vulnerável a técnicas de eliminação gaussiana para recuperar seu estado interno. Para mitigar isso, a implementação deste projeto adiciona **não-linearidades**:

```js
w = w ^ (w >>> 19) ^ (t ^ (t >>> 8));      // mistura (shift de xorshift)
nLa = (this.w + this.y) >>> 0;              // soma de estados
nLa = Math.imul(nLa, 0x2545f491) >>> 0;     // multiplicação por primo ímpar
nLa ^= nLa >>> 16;                          // xorshift de saída
return nLa >>> 0;
```

- A **soma de estados** (`w + y`) quebra a estrutura linear pura do xorshift.
- A **multiplicação por `0x2545f491`** (um multiplicador que preserva o período máximo) adiciona não-linearidade.
- Referências: [xorshift.pdf](https://vigna.di.unimi.it/ftp/papers/xorshift.pdf) e [cracking RNGs](https://jazzy.id.au/2010/09/22/cracking_random_number_generators_part_3.html).

### FNV-1a com Key Stretching (gerarNumero)

Responsável por transformar a chave em 4 seeds de 32 bits, que semearão os PRNGs.

```js
let hash = 0x811c9dc5n;              // offset basis do FNV-1a
for (let j = 0; j < 100000; j++) {
  for (let i = 0; i < str.length; i++) {
    hash ^= BigInt(str.charCodeAt(i));
    hash *= 0x01000193n;             // FNV prime
    hash = (hash >> 17n) ^ hash;     // misturas adicionais
    hash = (hash << 13n) ^ hash;
    hash &= 0xffffffffffffffffffffffffffffffffn; // 2^128 - 1
  }
  ...
}
```

- Usa **`BigInt`** para evitar o truncamento binário dos `Number` do JavaScript, mantendo um hash de **128 bits**.
- As misturas `(hash >> 17) ^ hash` e `(hash << 13) ^ hash` ampliam o **efeito avalanche** (um bit diferente na entrada muda muitos bits na saída).
- O laço de **100.000 iterações** é um *Key Stretching*: aumenta o custo computacional de cada tentativa, tornando inviável ataques de força bruta em massa (por exemplo, com GPUs).

### gerarHash — derivação de chave

Produz um hash de **256 caracteres hex** a partir da chave, que é usado para obter as seeds de todos os geradores.

```js
let seeds = this.gerarNumero(str);          // 4 seeds de 32 bits (128 bits no total)
let xor = new xorshift128(seeds[0], seeds[1], seeds[2], seeds[3]);
// 50 descartes iniciais + 32 saídas hex de 8 dígitos
```

O descarte inicial (warm-up de 50 valores) evita que saídas correlacionadas ao seed sejam expostas.

### Vetor de Inicialização (IV)

```js
gerarInitializationVector() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);      // aleatoriedade criptográfica do ambiente
  ...
}
```

- São gerados **3 IVs de 16 bytes** (48 bytes hex) concatenados.
- O IV atua como **salt**: é incorporado ao hash da chave (`gerarHash(chave + iv)`), fazendo com que **a mesma chave e a mesma mensagem gerem resultados diferentes a cada execução**. Isso protege contra **rainbow tables** (tabelas pré-computadas).
- O IV viaja junto com a mensagem cifrada (não é secreto — sua função é a *não-determinismo*, não o segredo).

### Seeds dos geradores

`startXorGenerators(iv)` usa fatias do hash de 256 caracteres para semear **4 PRNGs independentes**:

| Gerador           | Fatia do hash | Função                                    |
|-------------------|---------------|-------------------------------------------|
| `xor128Trashing`  | 0–64          | define o padrão `h` de inserção de lixo   |
| `xor128Rotation`  | 64–96         | valores de rotação e XOR do CBC           |
| `xor128Size`      | 128–192       | quantidade de lixo (`trashSize`)          |
| `xor128Numbers`   | 192–256       | bits aleatórios do lixo inserido          |

---

## Etapas da criptografia

### 1. Criptografia por bloco com CBC (criptR)

Transforma a string em uma lista de charCodes "embaralhados". É aqui que o **Cipher Block Chaining** entra:

```js
let previousBlock = generator.next() & 0xff;   // bloco inicial (aleatório)
for (let i = 0; i < string.length; i++) {
  let randomXorKey = generator.next();
  let rotationValue = (generator.next() % 8) + 1;
  let tmp = rotacionarDireita(charCode ^ previousBlock, rotationValue);
  tmp ^= (randomXorKey >>> 0) & 0xff;          // mantém no intervalo 0–255
  previousBlock = tmp;                          // encadeia o bloco atual
}
```

- **CBC**: cada charCode é combinado com o charCode anterior (via XOR) antes de ser transformado. Uma única mudança no texto altera **toda a cadeia** de blocos seguintes, tornando ineficaz o ataque de *plain-text conhecido* (conhecer trechos do texto original não ajuda a deduzir os demais).
- **Rotação bitwise**: cada bloco é rotacionado à direita por uma quantidade aleatória (1–8 bits), embaralhando a posição dos bits.
- **XOR com chave aleatória**: cada bloco é combinado com um valor pseudoaleatório.

A inversa (`uncriptR`) aplica as operações na ordem contrária: desfaz o XOR, rotaciona à esquerda e desfaz o XOR com o bloco anterior.

### 2. Obfuscação por inserção de lixo (criptT)

Transforma a lista de charCodes em binário e insere **bits de lixo** em pontos determinados por um padrão `h`:

```js
bits.push(bin[i][k]);
if ((k + 1) % h === 0 && k !== bin[i].length - 1) {
  for (let m = 0; m < this.trashSize; m++) {
    bits.push(generator.next() & 1);   // bits aleatórios "descartáveis"
  }
}
```

- Cada caractere vira 8 bits; a cada `h` bits inseridos, `trashSize` bits aleatórios são injetados.
- O padrão `h` e o tamanho do lixo `trashSize` são determinados pelas seeds derivadas da chave + IV — portanto **somente quem possui a chave sabe onde o lixo está**.
- Isso dificulta a análise estatística da mensagem (a distribuição de bits não corresponde mais à mensagem real).

### 3. Codificação final (criptTrashToString)

- O array binário achatado (com lixo) é preenchido até ser múltiplo de 8 bits.
- Cada grupo de 8 bits vira um byte em **hexadecimal**.

O resultado é uma string hex compacta que viaja junto com o MAC e o IV.

### 4. Código de Autenticação de Mensagem — MAC (gerarMAC)

```js
let hashSenha = this.gerarHash(senha);
let seeds = this.getSeedsByHex(hashSenha.substring(0, 32));
let xor128MAC = new xorshift128(seeds[0], seeds[1], seeds[2], seeds[3]);
for (let i = 0; i < texto.length; i++) {
  xor128MAC.x ^= code;              // mistura cada byte no estado
  xor128MAC.y ^= code << 7;
  xor128MAC.next();
}
// 100 descartes + 4 saídas hex de 8 dígitos = 32 caracteres
```

- O MAC é derivado do **texto cifrado + chave**. Qualquer alteração no texto ou uso de chave errada produz um MAC diferente.
- Segue o princípio **Encrypt-then-MAC**: a mensagem é cifrada **primeiro**, e o MAC é calculado **sobre a cifra** (não sobre o texto claro). Isso evita o "doom principle" descrito por Moxie Marlinspike.

---

## Etapas da descriptografia

`descriptografar(textoCriptografado, chave)`:

1. Divide a string pelo separador `-` em `[cifra, mac, iv]`.
2. **Verifica o formato** (precisa ter 3 partes).
3. Re-deriva as seeds com `startXorGenerators(iv)` usando a chave fornecida.
4. Recalcula o MAC esperado a partir da cifra e da chave.
5. Compara o MAC **em tempo constante**:
   ```js
   let diff = str1 ^ str2;
   if (str1.length !== str2.length) diff = 1;
   for (let i = 0; i < str1.length; i++) {
     diff |= str1.charCodeAt(i) ^ (str2.charCodeAt(i) || 0);
   }
   return diff === 0;
   ```
   O loop sempre percorre `str1.length` iterações e acumula as diferenças com `|`, aproveitando a propriedade `A ^ A = 0`. Assim o tempo de execução **independe** de onde as strings divergem, prevenindo **timing attacks**.
6. Se o MAC for inválido, lança erro e **não entrega nada** — o atacante nunca obtém o texto descriptografado ou mensagens de erro reveladoras. Se válido, remove o lixo, reverte o CBC e retorna a mensagem original.

---

## Formato da mensagem final

```
<cifra_hex>-<mac_32_hex>-<iv_48_hex>
```

- `cifra_hex`: bytes cifrados em hexadecimal.
- `mac_32_hex`: 32 caracteres hex (128 bits) de autenticação.
- `iv_48_hex`: 48 bytes hex de vetor de inicialização (salt).

> Observação: por usar o separador `-` no protocolo, a cifra e o IV são puramente hexadecimais, o que evita conflitos de parsing.

---

## Ataques que o projeto tenta mitigar

| Ataque                  | Defesa adotada                                                                                                   |
|-------------------------|------------------------------------------------------------------------------------------------------------------|
| **Plain-text attack**   | CBC: cada bloco depende do anterior; mudanças mínimas produzem resultados completamente diferentes.              |
| **Rainbow tables**      | IV aleatório como salt (mesmo texto + mesma chave → resultados diferentes) + hash com múltiplas iterações.       |
| **Álgebra linear / eliminação gaussiana** | Xorshift modificado com multiplicação por primo e soma de estados (não-linearidade).                |
| **Modificação de dados** | MAC (Encrypt-then-MAC): qualquer adulteração invalida a autenticação e bloqueia a descriptografia.               |
| **Timing attacks**      | `constantTimeCompare`: comparação em tempo constante via acumulação com XOR/OR.                                  |
| **Força bruta**         | Key stretching (100.000 iterações de FNV-1a) eleva o custo de cada tentativa.                                    |
| **Obfuscação/estatística** | Inserção de lixo binário cuja posição depende da chave, distorcendo a distribuição estatística da mensagem.    |

---

## Como usar

```js
import CriptoBitwise from "./CriptoBitwise.js";

const cripto = new CriptoBitwise();

const mensagem = "Mensagem super secreta!";
const chave = "minha-chave-secreta";

// Criptografar
const cifrado = cripto.criptografar(mensagem, chave);
console.log(cifrado); // <cifra_hex>-<mac_32_hex>-<iv_48_hex>

// Descriptografar
const original = cripto.descriptografar(cifrado, chave);
console.log(original); // Mensagem super secreta!

// Chave errada / mensagem adulterada → lança erro
try {
  cripto.descriptografar(cifrado, "chave-errada");
} catch (e) {
  console.log(e.message); // Mensagem corrompida, adulterada ou chave incorreta.
}
```

---

## Referências

- [Block cipher mode of operation — Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
- [Cipher block chaining — TechTarget](https://www.techtarget.com/searchsecurity/definition/cipher-block-chaining)
- [GeeksforGeeks — Block Cipher Modes of Operation](https://www.geeksforgeeks.org/ethical-hacking/block-cipher-modes-of-operation/)
- [Beyond Identity — Rainbow table attack](https://www.beyondidentity.com/glossary/rainbow-table-attack)
- [GeeksforGeeks — Rainbow table attack](https://www.geeksforgeeks.org/ethical-hacking/understanding-rainbow-table-attack/)
- [Vigna — An experimental exploration of xorshift generators (PDF)](https://vigna.di.unimi.it/ftp/papers/xorshift.pdf)
- [jazzy.id.au — Cracking random number generators, part 3](https://jazzy.id.au/2010/09/22/cracking_random_number_generators_part_3.html)
- [Erik Ringsmuth — Encrypt-then-MAC](https://medium.com/@ErikRingsmuth/encrypt-then-mac-fc5db94794a4)
- [Message authentication code — Wikipedia](https://en.wikipedia.org/wiki/Message_authentication_code)
- [Moxie Marlinspike — The Cryptographic Doom Principle](https://moxie.org/2011/12/13/the-cryptographic-doom-principle.html)
- [Timing attack — Wikipedia](https://en.wikipedia.org/wiki/Timing_attack)
- [ropesec.com — Timing attacks](https://ropesec.com/articles/timing-attacks/)
- [OWASP — Password Storage Cheat Sheet](https://owasp.org)
- [NIST SP 800-38A — Recommendation for Block Cipher Modes of Operation](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)

### Bibliografia

- MARSAGLIA, George. *Xorshift RNGs*. Journal of Statistical Software, 2003.
- BERNSTEIN, Daniel J. *ChaCha, a variant of Salsa20*. Workshop on Record in Cryptographic Hardware and Embedded Systems, 2008.
- KOCHER, Paul C. *Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems*. CRYPTO '96.
- KRAWCZYK, Hugo. *The Order of Encryption and Authentication for Protecting Communications*. CRYPTO 2001.

> **Aviso:** este projeto é um exercício educacional. Algoritmos criptográficos de produção devem usar primitivas auditadas (AES, ChaCha20, HMAC, etc.) em bibliotecas consolidadas. Criptografia "caseira" não deve ser usada para dados sensíveis sem revisão profissional.
