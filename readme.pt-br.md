# AESIO API

<p align="center">
  <a href="https://github.com/ferracini/AESIO">Inglês</a> | <span>Português do Brasil</span>
</p>

AESIO é uma API de implementação do Advanced Encryption Standard (AES) escrita em C e destinada à criptografia e descriptografia de arquivos e dados brutos.

## Modos de operação
+ Eletronic Codebook (ECB)\
```AESIO_MO_ECB```

+ Cipher Block Chaining (CBC)\
```AESIO_MO_CBC```

+ Counter (CTR)\
```AESIO_MO_CTR```

+ Galois/Counter Mode (GCM)\
```AESIO_MO_GCM```

## Tamanhos de chave suportados
+ 128 bits\
```AESIO_KL_128```

+ 192 bits\
```AESIO_KL_192```

+ 256 bits\
```AESIO_KL_256```

## Código de Autenticação de Mensagem (MAC)
+ HMAC-SHA1\
```AESIO_HM_SHA1```

+ HMAC-SHA256\
```AESIO_HM_SHA256```

+ GMAC\
None.\
O GMAC será automaticamente gerado se a flag ```AESIO_MO_GCM``` for definida.

## Ciphertext Stealing (CTS)
Nenhum preenchimento é aplicado aos blocos de mensagem nos modos ECB e CBC, ao invés disso o método CTS é usado por padrão.

## Uso

### Interface básica do AESIO
```C
/* Criptografa um arquivo.
 *
 * Caso a função seja bem sucedida, é retornado o valor AESIO_ERR_OK.
 *
 * Observações:
 * Essa função utiliza a função malloc para alocar o buffer que conterá os dados que serão criptogrados.
 * AesioEncryptFileStream é uma implementação equivalente que não faz uso da função malloc.
 */
AesioCode AesioEncryptFile(
	const char* destPath,	/* Caminho de destino.					*/
	const char* srcPath,	/* Caminho de origem.					*/
	const char* pwd,	/* Senha do usuário. String com terminação não-nula.	*/	
	const size_t pwdLen,	/* Comprimento da senha.				*/
	uint32_t* subKeys,	/* Ponteiro para as subchaves.				*/
	uint8_t* ad,		/* Dados adicionais para o modo GCM.			*/
	const uint64_t adSz,	/* Tamanho dos dados adicionais, em bytes.		*/
	const int moFlags);	/* Sinalizadores de bits para as configurações.		*/	

/* Criptografa um arquivo.
 *
 * Caso a função seja bem sucedida, é retornado o valor AESIO_ERR_OK.
 *
 * Observações:
 * Essa função não faz uso da função malloc, ou seja, não utiliza alocação dinâmica de memória.
 * Todas operações de entrada e saída são realizadas através de streams.
*/
AesioCode AesioEncryptFileStream(
	const char* destPath,	/* Caminho de destino.					*/
	const char* srcPath,	/* Caminho de origem.					*/
	const char* pwd,	/* Senha do usuário. String com terminação não-nula.	*/	
	const size_t pwdLen,	/* Comprimento da senha.				*/
	uint32_t* subKeys,	/* Ponteiro para as subchaves.				*/
	uint8_t* ad,		/* Dados adicionais para o modo GCM.			*/
	const uint64_t adSz,	/* Tamanho dos dados adicionais, em bytes.		*/
	const int moFlags);	/* Sinalizadores de bits para as configurações.		*/	

/* Descriptografa um arquivo.
 *
 * Caso a função seja bem sucedida, é retornado o valor AESIO_ERR_OK.
 *
 * Observações:
 * Essa função utiliza a função malloc para alocar o buffer que conterá os dados que serão descriptogrados.
 * AesioDecryptFileStream é uma implementação equivalente que não faz uso da função malloc.
*/
AesioCode AesioDecryptFile(
	const char* destPath,	/* Caminho de destino.					*/
	const char* srcPath,	/* Caminho de origem.					*/
	const char* pwd,	/* Senha do usuário. String com terminação não-nula.	*/
	const size_t pwdLen,	/* Comprimento da senha.				*/
	uint32_t* subKeys,	/* Ponteiro para as subchaves.				*/
	uint8_t* ad,		/* Dados adicionais para o modo GCM.			*/
	const uint64_t adSz);	/* Tamanho dos dados adicionais, em bytes.		*/

/* Descriptografa um arquivo.
 *
 * Caso a função seja bem sucedida, é retornado o valor AESIO_ERR_OK.
 *
 * Observações:
 * Essa função não faz uso da função malloc, ou seja, não utiliza alocação dinâmica de memória.
 * Todas operações de entrada e saída são realizadas através de streams.
*/
AesioCode AesioDecryptFileStream(
	const char* destPath,	/* Caminho de destino.					*/
	const char* srcPath,	/* Caminho de origem.					*/
	const char* pwd,	/* Senha do usuário. String com terminação não-nula.	*/
	const size_t pwdLen,	/* Comprimento da senha.				*/
	uint32_t* subKeys,	/* Ponteiro para as subchaves.				*/
	uint8_t* ad,		/* Dados adicionais para o modo GCM.			*/
	const uint64_t adSz);	/* Tamanho dos dados adicionais, em bytes.		*/

/* Criptografa dados brutos.
 *
 * Caso a função seja bem sucedida, é retornado o valor AESIO_ERR_OK.
 *
 * Observações:
 * Os ponteiros subKeys ou pwd podem ser nulos (NULL).
 * Se for passado um ponteiro para pwd, subKeys será ignorado. 
 * Se for passado um ponteiro para subKeys, pwd será ignorado.
*/
AesioCode AesioEncryptData(
	AESIO_CONTEXT* ioCtx,	/* Ponteiro para uma estrutura de contexto AESIO.	*/
	uint32_t* subKeys,	/* Ponteiro para as subchaves. 				*/
	const char* pwd,	/* Senha do usuário. String com terminação não-nula.	*/
	size_t pwdLen,		/* Comprimento da senha.				*/
	uint8_t* ad,		/* Dados adicionais para o modo GCM.			*/
	const uint64_t adSz);	/* Tamanho dos dados adicionais, em bytes.		*/

/* Descriptografa dados brutos.
 *
 * Caso a função seja bem sucedida, é retornado o valor AESIO_ERR_OK.
 *
 * Observações:
 * Os ponteiros subKeys ou pwd podem ser nulos (NULL).
 * Se for passado um ponteiro para pwd, subKeys será ignorado. 
 * Se for passado um ponteiro para subKeys, pwd será ignorado.
*/
AesioCode AesioDecryptData(
	AESIO_CONTEXT* ioCtx,	/* Ponteiro para uma estrutura de contexto AESIO.	*/
	uint32_t* subKeys,	/* Ponteiro para as subchaves. 				*/
	const char* pwd,	/* Senha do usuário. String com terminação não-nula.	*/		
	size_t pwdLen,		/* Comprimento da senha.				*/
	uint8_t* ad,		/* Dados adicionais para o modo GCM.			*/		
	const uint64_t adSz);	/* Tamanho dos dados adicionais, em bytes.		*/

/* Inicializa um contexto AESIO.
 *
 * Caso a função seja bem sucedida, é retornado o valor AESIO_ERR_OK.
 *
 * Observações:
 * Se for passado um ponteiro para iVec, iVec será copiado para o contexto.
 * Se iVec for nulo (NULL), um novo vetor de inicialização será gerado no contexto.
*/
AesioCode AesioInit(
	AESIO_CONTEXT* ctx, 	/* Ponteiro para uma estrutura de contexto AESIO.	*/
	uint8_t* buffer,	/* Ponteiro para um buffer que contém a entrada.	*/
	size_t buffSz,		/* Tamanho do buffer, em bytes. 			*/
	uint32_t bFlags,	/* Sinalizadores de bits para as configurações.		*/
	uint32_t* iVec);	/* Ponteiro para um vetor de inicialização de 128 bits.	*/

/* Libera um contexto AESIO.
 *
 * Observações:
 * A estrutura de contexto AESIO deve ser inicializada corretamente
 * antes de ser passada para esta função.
*/
void ReleaseAesioContext(
	AESIO_CONTEXT* ctx, 	/* Ponteiro para uma estrutura de contexto AESIO.	*/
	_Bool freeAesBuff); 	/* Libera o buffer do AES alocado na memória.		*/

/* Gera números pseudo-aleatórios para o vetor de inicialização (IV).
 *
 * Caso a função seja bem sucedida, é retornado o valor AESIO_ERR_OK.
 *
 * Observações:
 * O ponteiro do vetor de inicialização (iVec) não pode ser nulo (NULL).
*/
AesioCode InitRandVec(
	uint32_t* iVec );	/* Ponteiro para o vetor de inicialização de 128 bits.	*/

/* Gera subchaves para o AES.
 * 
 * Caso a função seja bem sucedida, é retornado o valor AESIO_ERR_OK.
 * 
 * Observações:
 * Os ponteiros subKeys e pwd não podem ser nulos (NULL).
 * O valor de kBlockSize deve ser 16 (AES-128), 24(AES-192) ou 32 (AES-256).
*/
AesioCode KeySchedule(
	uint32_t* subKeys,	/* Ponteiro para as subchaves.				*/
	const char* pwd,	/* Senha do usuário. String com terminação não-nula.	*/		
	const size_t pwdSz,	/* Tamanho da senha de usuário, em bytes.		*/	
	size_t kBlockSize);	/* Tamanho da chave, em bytes.				*/
```
### Compilar

```sh
make
```

## Dependências

+ O código está escrito em C padrão;
+ Não há dependência de outras bibliotecas;
+ Apenas a implementação do modo GCM utiliza instruções SSE.


## Exemplo
O código abaixo mostra como criptografar uma string.
```C
char str[] = "This is my cool string to be encrypted and decrypted.";
char pwd[] = "thisismypassword";

AesioCode res;
uint32_t subKeys[AES_128_SUBKEYS_COUNT];
AESIO_CONTEXT ioCtx = { 0 };

/* Inicializa o contexto */
res = AesioInit(&ioCtx, (uint8_t*)str, sizeof(str) - 1, AESIO_MO_CTR | AESIO_HM_SHA1 | AESIO_KL_128, NULL);
if (res != AESIO_ERR_OK)
{
	goto cleanup;
}

/* Expansão de chaves */
re = KeySchedule(subKeys, pwd, strlen(pwd), AESIO_128_KSZ);
if (res != AESIO_ERR_OK)
{
	goto cleanup;
}

/* Criptografa a string */
res = AesioEncryptData(&ioCtx, subKeys, pwd, strlen(pwd), NULL, 0);
if (res != AESIO_ERR_OK)
{
	goto cleanup;
}

/*
 * Faça algo com a string criptografada aqui.
 */

/* Descriptografe a string quando terminar */
res = AesioDecryptData(&ioCtx, subKeys, pwd, strlen(pwd), NULL, 0);
if (res != AESIO_ERR_OK)
{
	goto cleanup;
}

cleanup:
/* Libera o contexto */
ReleaseAesioContext(&ioCtx, FALSE);
/* Limpe as variáveis locais por razões de segurança */
memset(subKeys, 0, AESIO_128_KSZ);

```
Veja o arquivo `/src/tests.c` para mais exemplos.


## Autor

* **Diego Ferracini Bando** - [ferracini](https://github.com/ferracini)

## Licença

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> Copyright (c) 2019 Diego Ferracini Bando
> 
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
> 
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
> 
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.
