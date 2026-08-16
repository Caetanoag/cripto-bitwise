/**
 * Criptografador utilizando obfuscação, operadores bitwise e algumas estratégias de
 * segurança para dificultar ataques comuns em criptografia,
 *  * Cobre:
 *  * - Plain-Text Attack
 *    Protegido contra isso por meio da arquitetura do criptR, que utiliza
 *    Cipher Block Chaining (CBC) para garantir que uma simples mudança no texto
 *    gere um resultado muito diferente.
 *  *    https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
 *    https://www.techtarget.com/searchsecurity/definition/cipher-block-chaining
 *    https://www.geeksforgeeks.org/ethical-hacking/block-cipher-modes-of-operation/
 *  * - Rainbow Tables
 *    Protegido por meio do uso de hashes com salt (IV) e múltiplas iterações (Ket Stretching)
 *    do gerador de números aleatórios. Essa multiplas iterações aumentam o tempo
 *    que leva para executar uma tentativa, tornando ineficiente ataques de força bruta,
 *    enquanto que o IV garante que o mesmo texto, com a mesma chave, gere resultados
 *    diferentes a cada execução.
 *
 *    https://www.beyondidentity.com/glossary/rainbow-table-attack
 *    https://www.geeksforgeeks.org/ethical-hacking/understanding-rainbow-table-attack/
 * - Ataques de algebra linear
 *    O xorshift128, na sua forma original, é vulnerável a ataques que envolvem eliminação
 *    gaussiana e outras técnicas para resolver equações linerares. Para resolver isso,
 *    alterei o seu funcionamento interno, adicionando multiplicações com números primos e
 *    somas de estados.
 *  *    https://math.okstate.edu/people/binegar/4513-F98/4513-l11.pdf
 *    https://vigna.di.unimi.it/ftp/papers/xorshift.pdf
 *    https://jazzy.id.au/2010/09/22/cracking_random_number_generators_part_3.html
 *    (Z3 solver também serve para justificar a vulnerabilidade do xorshift original)
 *
 *
 * - Ataques de modificação de dados
 *    Protegido graças à implementação de um sistema de validação, que identifica,
 *    por meio da chave e do conteúdo, qual valor o MAC deveria ter, e qual ele tem.
 *    Se os valores forem diferentes, o código para e não entrega nada ao usuário, evitando
 *    que alguém use as informações que o criptografador enviaria para quebrar a segurança.
 *
 *    https://medium.com/@ErikRingsmuth/encrypt-then-mac-fc5db94794a4
 *    https://en.wikipedia.org/wiki/Message_authentication_code
 *    https://moxie.org/2011/12/13/the-cryptographic-doom-principle.html
 *  * - Timing Attacks
 *    O sistema de MAC precisa comparar duas Strings, a comparação no javascript funciona
 *    percorrendo cada item até encontrar um diferente, o que às vezes leva tempos diferentes
 *    dependendo das strings comparadas. Por isso, a função constantTimeCompare utiliza da
 *    propriedade do operador XOR (A ^ A = 0) para garantir o tempo constate, sempre percorrendo
 *    as mesmas iterações, indepentende dos códigos MAC serem iguais ou não.
 *
 *    https://www.youtube.com/watch?v=2-zQp26nbY8
 *    https://ropesec.com/articles/timing-attacks/
 *    https://en.wikipedia.org/wiki/Timing_attack
 *
 *
 */

/**
 * Algumas referências bibliográficas, não li por completo, mas utilizei junto das outras
 * que coloquei acima.
 *  * MARSAGLIA, George. Xorshift RNGs. Journal of Statistical Software, 2003.
 *  * BERNSTEIN, Daniel J. ChaCha, a variant of Salsa20. Workshop on Record in Cryptographic
 * Hardware and Embedded Systems, 2008.
 *
 * KOCHER, Paul C. Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS,
 * and Other Systems. CRYPTO '96.
 *
 * KRAWCZYK, Hugo. The Order of Encryption and Authentication for Protecting Communications.
 * CRYPTO 2001.
 *
 * OWASP Foundation. Password Storage Cheat Sheet. Disponível em: owasp.org.
 *  * NIST. SP 800-38A: Recommendation for Block Cipher Modes of Operation.
 *  * VIGNA, Sebastiano. An experimental exploration of Marsaglia's xorshift generators,
 * scrambled. ACM Transactions on Mathematical Software, 2016
 */
// ========================================================================

// ========================================================================
/**  * Gerador de números aleatorios baseados no XORSHIFT, porém com não-lineraridade
 *  * Adaptado para dificultar ataques de algebra linear e eliminação gaussiana.
 */
class xorshift128 {
  constructor(seed1, seed2, seed3, seed4) {
    this.x = seed1 >>> 0 || 0xfff212e;
    this.y = seed2 >> 0 || 1234567;
    this.z = seed3 >> 0 || 0xf93242ff;
    this.w = seed4 >> 0 || 0xfeaa2;
  }
  next() {
    let t = this.x;
    t ^= t << 11;
    t = t >>> 0;
    this.x = this.y;
    this.y = this.z;
    this.z = this.w;
    let w = this.w;
    w = w ^ (w >>> 19) ^ (t ^ (t >>> 8));
    this.w = w >>> 0;
    let nLa = (this.w + this.y) >>> 0;
    nLa = Math.imul(nLa, 0x2545f491) >>> 0;
    nLa ^= nLa >>> 16;
    return nLa >>> 0;
  }
}
// ========================================================================

class CriptoBitwise {
  constructor() {
    this.binType = 8; // quantidade de bits que cada charCode precisa ter.

    // Variaveis de estado internas
    this.chaveEntrada = "";
    this.xor128Trashing = null;
    this.trashing = null;
    this.trashSize = null;
    this.xor128Numbers = null;
    this.xor128Rotation = null;
    this.xor128Size = null;
  }

  // ========================================================================

  /**
   * Gera um código de autenticação (MAC). Garante que a mensagem não foi alterada,
   * protegendo contra ataques relacionados à inserção ou modificação de dados.
   * @param {String} texto
   * @param {String} senha
   * @returns {String} codigo MAC de 32 caracteres.
   */
  gerarMAC(texto, senha) {
    let hashSenha = this.gerarHash(senha);
    let seeds = this.getSeedsByHex(hashSenha.substring(0, 32));
    let xor128MAC = new xorshift128(seeds[0], seeds[1], seeds[2], seeds[3]);
    for (let i = 0; i < texto.length; i++) {
      let code = texto.charCodeAt(i);
      xor128MAC.x ^= code;
      xor128MAC.y ^= code << 7;
      xor128MAC.next();
    }
    for (let i = 0; i < 100; xor128MAC.next(), i++);
    let parte1 = (xor128MAC.next() >>> 0).toString(16).padStart(8, "0");
    let parte2 = (xor128MAC.next() >>> 0).toString(16).padStart(8, "0");
    let parte3 = (xor128MAC.next() >>> 0).toString(16).padStart(8, "0");
    let parte4 = (xor128MAC.next() >>> 0).toString(16).padStart(8, "0");

    return parte1 + parte2 + parte3 + parte4;
  }
  /**
   * Gera um vetor de inicialização (IV), utilizado como "salt" na criptografia,
   * melhorando a segurança contra ataques de rainbow tables.
   * @returns String
   */
  gerarInitializationVector() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  /**
   * Função para comparar duas strings em tempo constate, buscando prevenir ataques
   * baseados no tempo de execução (Timed Attacks).
   *  * @param {String} mac_esperado
   * @param {String} mac_recebido
   * @returns Boolean
   */
  constantTimeCompare(str1, str2) {
    let diff = str1 ^ str2; // Se ambas forem diferentes, o diff já será diferente de 0.
    if (str1.length !== str2.length) {
      diff = 1;
    }
    for (let i = 0; i < str1.length; i++) {
      diff |= str1.charCodeAt(i) ^ (str2.charCodeAt(i) || 0); // evita fazer xor com "", undefined ou null.
    }
    return diff === 0;
  }
  /**
   * Recebe uma string hexadecimal de 32 caracteres e a quebra em 4 seeds para o xorshift128.
   * @param {string} string_hexadecimal
   * @returns Numbers[] -> uint32, uint32, uint32, uint32
   */

  getSeedsByHex(hex) {
    let seed1 = parseInt(hex.substring(0, 8), 16);
    let seed2 = parseInt(hex.substring(8, 16), 16);
    let seed3 = parseInt(hex.substring(16, 24), 16);
    let seed4 = parseInt(hex.substring(24, 32), 16);
    return [seed1, seed2, seed3, seed4];
  }
  /**
   * Implementação do FNV-1a, que gera 4 seeds de 32 bits a partir de uma string.
   *  * Além do FNV-1a, adicionei também um sistema de key stretching, que itera
   * o hash 100.000 vezes, para aumentar o tempo que uma GPU leva para executar o programa.
   *  * Alta difusão e efeito avalanche.
   *  * @param {string} Chave
   * @returns Numbers[] -> uint32, uint32, uint32, uint32
   */
  gerarNumero(str) {
    let hash = 0x811c9dc5n; // "Offset Basis"
    for (let j = 0; j < 100000; j++) {
      for (let i = 0; i < str.length; i++) {
        hash ^= BigInt(str.charCodeAt(i));
        hash *= 0x01000193n; // Utilizando multiplicacao com BigInt para não perder Bits e tornar 128 bits
        /**
         * Utiliza BigInt para evitar o truncamento binário que o Javascript faz quando recebe
         * um overflow na classe Number. Sem isso, o hash perderia bits importantes graças à
         * multiplição por 0x01000193n, que é um número grande.
         */
        hash = (hash >> 17n) ^ hash;
        hash = (hash << 13n) ^ hash;
        hash &= 0xffffffffffffffffffffffffffffffffn; // coloca no limite de 2^128-1 (hexadecimal)
      }
      hash ^= hash >> 32n;
      hash ^= hash << 13n;
      hash &= 0xffffffffffffffffffffffffffffffffn; // coloca no limite de 2^128-1 (hexadecimal)
    }
    let seed1 = Number(hash & 0xffffffffn);
    let seed2 = Number((hash >> 32n) & 0xffffffffn);
    let seed3 = Number((hash >> 64n) & 0xffffffffn);
    let seed4 = Number((hash >> 96n) & 0xffffffffn);
    return [seed1, seed2, seed3, seed4];
  }
  /**
   * Recebe uma chave e a transforma em um hash com 256 caracteres
   * para melhorar a seguranca contra Rainbow Tables
   * @param {string} Chave
   * @returns Hash256Chars
   */
  gerarHash(str) {
    let seeds = this.gerarNumero(str);
    let xor = new xorshift128(seeds[0], seeds[1], seeds[2], seeds[3]);
    let hash = "";
    for (let i = 0; i < 50; i++, xor.next());
    for (let i = 0; i < 32; i++) {
      let randomNum = xor.next();
      let hexaDecimal = (randomNum >>> 0).toString(16).padStart(8, "0");
      hash += hexaDecimal;
    }
    return hash;
  }
  // ========================================================================

  // ========================================================================'
  /**
   * Recebe um número e o representa na quantidade
   * definida de bits
   * @param {Number} numero
   * @param {Number} quantidade_de_bits
   * @returns String binária
   */
  getBin(num = 0, bits) {
    let out = "";
    for (let i = bits - 1; i >= 0; i--) {
      out = out + String((num >> i) & 1);
    }
    return out;
  }
  /**
   * Rotaciona os bits para direita em uma quantidade especifica
   *  * rotacionar(5,2) -> 101(5)_1 = 110 -> 101(5)_2 = 011(3).
   * @param {Number} numero
   * @param {Number} bits_de_deslocamento
   * @returns Inteiro rotacionado
   */
  rotacionarDireita(num = 0, deslocar = 0) {
    return (
      ((num >>> (deslocar % this.binType)) |
        (num << (this.binType - (deslocar % this.binType)))) &
      (2 ** this.binType - 1)
    );
  }
  /**
   * Rotaciona os bits para esquerda em uma quantidade especifica
   *  * rotacionar(3,2) -> 011(3)_1 = 110 -> 110(3)_2 = 101(5).
   * @param {Number} numero
   * @param {Number} bits_de_deslocamento
   * @returns Inteiro rotacionado
   */
  rotacionarEsquerda(num = 0, deslocar = 0) {
    return (
      ((num << (deslocar % this.binType)) |
        (num >>> (this.binType - (deslocar % this.binType)))) &
      (2 ** this.binType - 1)
    );
  }
  /**
   *  * Recebe uma string e um gerador de numero aleatório, cada caracter dessa string
   * é rotacionado de uma forma por um numero aleatório, passa por um xor
   * e então o seu charCode é salvo.
   *  * Implementação de Cipher Block Chaining (CBC), XOR e rotações bitwise.
   *  * Cada charCode depende do anterior, tornando ataques de plain-text ineficazes.
   * @param {string} string
   * @param {object} generator
   * @returns String[] - charCodes
   */
  criptR(string, generator) {
    let valueList = [];
    let previousBlock = generator.next() & 0xff;
    for (let i = 0; i < string.length; i++) {
      let randomXorKey = generator.next();
      let rotationValue = (generator.next() % this.binType) + 1;
      let tmp = this.rotacionarDireita(
        string.charCodeAt(i) ^ previousBlock,
        rotationValue,
      );
      tmp ^= (randomXorKey >>> 0) & 0xff;
      /**
       * Isso é muito utilizado quando queremos colocar um número no intervalo 0-255.
       * randomXorKey >>> 0 torna o número positivo
       * dai o & 0xFF o coloca no intervalo de 0 ate 0xFF, que é 255 em decimal.
       */
      previousBlock = tmp;
      valueList.push(tmp);
    }
    return valueList;
  }
  /**
   * Recebe um array de charCodes e os rotaciona de forma oposta ao criptR para recuperar
   * a mensagem original
   * Precisa receber o exato mesmo gerador que criptR
   * @param {Array} arr
   * @param {Object} generator
   * @returns [] - charCodes
   */
  uncriptR(arr, generator) {
    let valueList = [];
    let previousBlock = generator.next() & 0xff;
    for (let i = 0; i < arr.length; i++) {
      let randomXorKey = generator.next();
      let rotationValue = (generator.next() % this.binType) + 1;
      let tmp = Number(arr[i]);
      let cifrado = arr[i];
      tmp ^= (randomXorKey >>> 0) & 0xff;
      tmp = this.rotacionarEsquerda(tmp, rotationValue);
      tmp ^= previousBlock;
      previousBlock = cifrado;
      valueList.push(tmp);
    }
    return valueList;
  }
  /**
   * Recebe uma string e retorna uma matriz com o binário separado em arrays de bits.
   * Cada array dessa matriz tem 8 bits.
   * @param {string} palavra
   * @returns matriz_binaria
   */

  generate2DBinaryCode(word) {
    // recebe uma string e gera o codigo binario no formato [][];
    let bits = [];
    for (let letter of word) {
      let bit = [];
      for (let i = this.binType - 1; i >= 0; i--) {
        bit.push(1 & (letter.charCodeAt(0) >> i));
      }
      bits.push(bit);
    }
    return bits;
  }
  /**
   * Recebe uma matriz binária e insere lixo em cada um dos bits com base em um padrao h
   * e um gerador aleatorio definido
   *  * @param {string} word
   * @param {Number} h
   * @param {object} generator
   * @returns matriz_com_lixo
   */
  insertTrash(word, h, generator) {
    let bin = this.generate2DBinaryCode(word);
    let out = [];
    for (let i = 0; i < bin.length; i++) {
      let bits = [];
      for (let k = 0; k < bin[i].length; k++) {
        bits.push(bin[i][k]);
        if ((k + 1) % h === 0 && k !== bin[i].length - 1) {
          for (let m = 0; m < this.trashSize; m++) {
            bits.push(generator.next() & 1);
          }
        }
      }
      out.push(bits);
    }
    return out;
  }
  /**
   * Recebe uma matriz e a transforma em uma array achatada
   * @param {Array} matriz_binaria
   * @returns array_flattened
   */
  flatten(arr) {
    let arrFinal = [];
    for (let i = 0; i < arr.length; i++) {
      for (let j = 0; j < arr[i].length; j++) {
        arrFinal.push(arr[i][j]);
      }
    }
    return arrFinal;
  }
  function;
  criptTrashToString(arr) {
    while (arr.length % this.binType !== 0) {
      arr.push(0);
    }
    let str = "";
    for (let i = 0; i < arr.length; i += this.binType) {
      let add = parseInt(arr.slice(i, i + this.binType).join(""), 2).toString(
        16,
      );
      if (add.length < 2) {
        add = "0" + add;
      }
      str += add;
    }
    return str;
  }
  criptT(word, trashing, generator) {
    let arr = this.flatten(this.insertTrash(word, trashing, generator));
    return arr;
  }
  /**
   * Recebe um array achatado com lixo inserido, e a transforma em uma
   * matriz com os bits do tamanho do lixo.
   * @param {Array} array_binaria
   * @param {Number} padrao_rotacao
   * @returns matriz binaria com lixo
   */
  unflattenArrayWithTrash(arr, h) {
    let bits = [];
    for (
      let i = 0;
      i < arr.length;
      i += this.binType + this.trashSize * Math.floor((this.binType - 1) / h)
    ) {
      bits.push(
        arr.slice(
          i,
          i +
            this.binType +
            this.trashSize * Math.floor((this.binType - 1) / h),
        ),
      );
    }
    return bits;
  }
  /**
   * @param {Array} matriz_binaria_com_lixo
   * @param {*} padrao_rotacao
   * @returns matriz binaria sem lixo
   */
  removeTrash(arr, h) {
    let output = [];
    for (let i = 0; i < arr.length; i++) {
      let letter = arr[i];
      let letterNoTrash = [];
      let index = 0;
      while (index < letter.length) {
        for (let m = 0; m < h && index < letter.length; m++, index++) {
          letterNoTrash.push(letter[index]);
        }
        index += this.trashSize;
      }
      output.push(letterNoTrash);
    }
    return output;
  }
  /**
   * Recebe uma array com lixo inserido e retira esse lixo para recuperar
   * a mensagem original
   *  * @param {Array} resultado_criptT
   * @param {Number} padrao_rotacao
   * @returns array_achata_sem_lixo
   */
  uncriptT(arr, h) {
    return this.flatten(
      this.removeTrash(this.unflattenArrayWithTrash(arr, h), h),
    );
  }
  /**
   * Criptografia principal, utiliza todas funções auxiliares definidas acima
   * para gerar uma mensagem criptografada, utilizando algoritmos matemáticos complexos
   * e um sistema de segurança por obfuscação de dados (Inserção de lixo)
   * @param {String} texto
   * @returns String criptografada em hexadecimal
   */
  criptAll(input) {
    let ins = input;
    return this.criptTrashToString(
      this.criptT(
        this.criptR(ins, this.xor128Rotation).join(","),
        this.trashing,
        this.xor128Numbers,
      ),
    );
  }
  /**
   * Recebe uma string hexadecimal e a transforma de volta em uma matriz binária.
   *  *  * @param {String} texto
   * @returns [ [bits], [bits], [bits] ... ]
   */
  unHex(texto) {
    let a = [];
    for (let i = 0; i < texto.length; i += 2) {
      a.push(texto.slice(i, i + 2));
    }
    let bin = [];
    for (let j = 0; j < a.length; j++) {
      bin.push(this.getBin(parseInt(a[j], 16), 8));
    }
    let bits = [];
    for (let d = 0; d < bin.length; d++) {
      let bit = [];
      for (let k = 0; k < bin[d].length; k++) {
        bit.push(Number(bin[d][k]));
      }
      bits.push(bit);
    }
    return bits;
  }
  /**
   * Recebe um array de bits sem lixo e os transforma em uma string
   * com os charCodes originais separados por virgula.
   *  * @param {Array} arr
   * @returns string_final
   */
  bitsToCharCode(arr) {
    let a = [];
    let a2 = [];
    for (let i = 0; i < arr.length - (arr.length % 8); i++) {
      if (a2.length !== 8) {
        a2.push(arr[i]);
      }
      if (a2.length == 8) {
        a.push(a2);
        a2 = [];
      }
    }
    let final = "";
    for (let k = 0; k < a.length; k++) {
      let str = "";
      for (let j = 0; j < a[k].length; j++) {
        str += String(a[k][j]);
      }
      final += String.fromCharCode(parseInt(str, 2));
    }
    return final;
  }
  /**
   * Recebe um array de charCodes e os transforma nas suas
   * respectivas letras, formando a string original.
   * @param {Array} arr
   * @returns
   */
  arrNumberToString(arr) {
    let out = "";
    for (let i = 0; i < arr.length; i++) {
      out += String.fromCharCode(arr[i]);
    }
    return out;
  }
  /**
   * O exato oposto da função criptAll, recupera a mensagem original.
   * @param {String} texto
   * @returns mensagem original
   */
  uncriptAll(texto) {
    if (texto == "") {
      return "";
    }
    return this.arrNumberToString(
      this.uncriptR(
        this.bitsToCharCode(
          this.uncriptT(this.flatten(this.unHex(texto)), this.trashing),
        ).split(","),
        this.xor128Rotation,
      ),
    );
  }
  /**
   * Recebe o Vetor de Inicialização (IV), utiliza ele como Salt para o hash então
   * cria as Seeds dos geradores. Garantindo Senhas e chaves Iguais - > Resultados diferentes
   * em várias iterações.
   * @param {String} iv
   */
  startXorGenerators(iv) {
    let hash = this.gerarHash(this.chaveEntrada + iv);
    let seedsTrashing = this.getSeedsByHex(hash.substring(0, 64));
    this.xor128Trashing = new xorshift128(
      seedsTrashing[0],
      seedsTrashing[1],
      seedsTrashing[2],
      seedsTrashing[3],
    );
    this.trashing = (this.xor128Trashing.next() % 8) + 1;
    let seedsNumbers = this.getSeedsByHex(hash.substring(192, 256));
    this.xor128Numbers = new xorshift128(
      seedsNumbers[0],
      seedsNumbers[1],
      seedsNumbers[2],
      seedsNumbers[3],
    );
    let seedsRotation = this.getSeedsByHex(hash.substring(64, 96));
    this.xor128Rotation = new xorshift128(
      seedsRotation[0],
      seedsRotation[1],
      seedsRotation[2],
      seedsRotation[3],
    );
    let seedsSize = this.getSeedsByHex(hash.substring(128, 192));
    this.xor128Size = new xorshift128(
      seedsSize[0],
      seedsSize[1],
      seedsSize[2],
      seedsSize[3],
    );
    this.trashSize = (this.xor128Size.next() % 8) + 1;
  }
  criptografar(message, chave) {
    this.chaveEntrada = chave;
    let iv =
      this.gerarInitializationVector() +
      this.gerarInitializationVector() +
      this.gerarInitializationVector();
    this.startXorGenerators(iv);
    let crypt = this.criptAll(message);
    let mac = this.gerarMAC(crypt, this.chaveEntrada);
    let stringFinal = crypt + "-" + mac + "-" + iv;
    return stringFinal;
  }

  descriptografar(textoCriptografado, chave) {
    this.chaveEntrada = chave;
    let arrMessage = textoCriptografado.split("-");

    if (arrMessage.length < 3) throw new Error("Formato inválido.");

    let crypt = arrMessage[0];
    let macMessage = arrMessage[1];
    let iv = arrMessage[2];

    this.startXorGenerators(iv);
    let macEsperado = this.gerarMAC(crypt, this.chaveEntrada);
    if (!this.constantTimeCompare(macEsperado, macMessage)) {
      throw new Error("Mensagem corrompida, adulterada ou chave incorreta.");
    } else {
      return this.uncriptAll(crypt);
    }
  }
}
export default CriptoBitwise;
