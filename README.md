# Meowing Cat's RSA/PKE implementation (Catcrypt)

[![GitHub issues](https://img.shields.io/github/issues/rohanrhu/catcrypt?style=flat-square&color=red)](https://github.com/rohanrhu/catcrypt/issues)
[![GitHub forks](https://img.shields.io/github/forks/rohanrhu/catcrypt?style=flat-square)](https://github.com/rohanrhu/catcrypt/network)
[![GitHub stars](https://img.shields.io/github/stars/rohanrhu/catcrypt?style=flat-square)](https://github.com/rohanrhu/catcrypt/stargazers)
[![Support me on Patreon](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fshieldsio-patreon.vercel.app%2Fapi%3Fusername%3DEvrenselKisilik%26type%3Dpatrons&style=flat-square)](https://patreon.com/EvrenselKisilik)
[![Donate with BTC](https://shields.io/badge/donate-bc1qhvlc762kwuzeawedl9a8z0duhs8449nwwc35e2-yellow?logo=bitcoin&style=flat-square)](#donate)

Simple RSA public key encryption library for C/C++.

## Features

Catcrypt can do these:

* Generating RSA keypairs
* Exporting RSA keys as HEX representations
* Importing RSA keys from HEX
* Encrypting data
* Decrypting data
* Signing data
* Exporting signatures into string
* Importing signatures from string
* Verifying data by signature

## How it works?

Jump to the [Example](#example) if you wanna be quick.

> [!CAUTION]
> **Please read this:**
> This RSA library seems to be safe but THERE IS NO ANY GUARANTEE!
> The prime number generation seems to be safe enough and impossible (I'M NOT SURE and THERE IS NO ANY GUARANTEE) to break.
> **Using this library or not is %100 in your responsibility.**

I wrote this library for only signing & verifying purpose for my game server and
just wanted to share it as open source by extracting from my game server
with some other things like my string and reference counting and referencing implementations.

> [!WARNING]
> The library uses 2048 bit keys by default.
> It has a weird "addition loop" thing for random prime number generation and I'm not sure if it is better or worse for entropy. (I'll visualize it and see if it is or not.)
> It uses 65537 for public key exponent.
> This RSA implementation is not compatible with any other RSA implementation.
> It uses my own format for encrypted data.

## Build, Link and Use

### Include

```c
#include "rsa.h"
```

### Building and Linking

You can just build and link `rsa.o` and use `rsa.h`. Don't forget to use `-O3` flag for compilation.

Using `make` will build catcrypt and examples:

```bash
cd /path/to/catcrypt
make
cd /path/to/your/app
gcc -o app.exe app.c \
    /path/to/catcrypt/rsa.o -I /path/to/catcrypt \
    ./catcrypt/thirdparty/gmp-6.3.0/.libs/libgmp.a -I ./catcrypt/thirdparty/gmp-6.3.0
```

You need to link GNU MP Big Number library too like this ^^.

## Usage and API Reference

Here you can see everything:

```c
#define CATCRYPT_RSA_PUB_EXPONENT 65537
#define CATCRYPT_RSA_PRIME_BITS 2048
#define CATCRYPT_RSA_PRIME_REPS 50
#define CATCRYPT_RSA_BLOCK_SIZE 128

#define CATCRYPT_MPZ_ENDIAN 1
#define CATCRYPT_MPZ_ORDER 1

typedef uint8_t catcrypt_rsa_random_seed_adds_t;
#define CATCRYPT_RSA_RANDOM_SEED_ADDS_MASK 20 // 1 to 2 ^ ((sizeof(catcrypt_rsa_random_seed_adds_t) * 8) - 1)

typedef struct catcrypt_rsa_keypair catcrypt_rsa_keypair_t;
typedef struct catcrypt_rsa_key catcrypt_rsa_key_t;
typedef struct catcrypt_rsa_encrypted catcrypt_rsa_encrypted_t;

struct catcrypt_rsa_key {
    REF_COUNTEDIFY();
    mpz_t e;
    mpz_t n;
};

struct catcrypt_rsa_keypair {
    REF_COUNTEDIFY();
    catcrypt_rsa_key_t* pubkey;
    catcrypt_rsa_key_t* privkey;
};

struct catcrypt_rsa_encrypted {
    REF_COUNTEDIFY();
    catcrypt_string_t* data;
    catcrypt_rsa_key_t* key;
};

uint32_t catcrypt_rsa_hash_h32(char* str);
uint32_t catcrypt_rsa_hash_h32__n(char* data, ssize_t length);

bool catcrypt_rsa_random_seed(unsigned char* seed, size_t size);
void catcrypt_rsa_random_prime(mpz_t num);

catcrypt_rsa_key_t* catcrypt_rsa_key_new();
void catcrypt_rsa_key_free(catcrypt_rsa_key_t* key);
catcrypt_rsa_keypair_t* catcrypt_rsa_keypair_new();
void catcrypt_rsa_keypair_free(catcrypt_rsa_keypair_t* keypair);

catcrypt_rsa_encrypted_t* catcrypt_rsa_encrypted_new();
void catcrypt_rsa_encrypted_set_key(catcrypt_rsa_encrypted_t* encrypted, catcrypt_rsa_key_t* key);
void catcrypt_rsa_encrypted_set_data(catcrypt_rsa_encrypted_t* encrypted, catcrypt_string_t* data);
void catcrypt_rsa_encrypted_free(catcrypt_rsa_encrypted_t* encrypted);
catcrypt_rsa_encrypted_t* catcrypt_rsa_encrypt(catcrypt_string_t* data, catcrypt_rsa_key_t* pubkey);
catcrypt_string_t* catcrypt_rsa_decrypt(catcrypt_rsa_encrypted_t* encrypted, catcrypt_rsa_key_t* privkey);

catcrypt_string_t* catcrypt_rsa_key_to_bin(catcrypt_rsa_key_t* key);
catcrypt_rsa_key_t* catcrypt_rsa_key_from_bin(catcrypt_string_t* hex);

catcrypt_string_t* catcrypt_rsa_key_to_hex(catcrypt_rsa_key_t* key);
catcrypt_rsa_key_t* catcrypt_rsa_key_from_hex(catcrypt_string_t* hex);

catcrypt_string_t* catcrypt_rsa_sign(catcrypt_string_t* data, catcrypt_rsa_key_t* privkey);
bool catcrypt_rsa_verify(catcrypt_string_t* data, catcrypt_string_t* signature, catcrypt_rsa_key_t* pubkey);
catcrypt_string_t* catcrypt_rsa_signature_to_hex(catcrypt_string_t* signature_bin);
catcrypt_string_t* catcrypt_rsa_signature_from_hex(catcrypt_string_t* signature_hex);
```

It is easy to understand I think. Please look at the example usage. (`./examples/test`)

## Types (Strings and Reference Counting & Reference)

Actually, I wrote this library for one of my projects and extracted it to make it an independent open source library.

It has my strings and reference counting and reference system that you can easily understand how it works in the following example.

### Strings (`catcrypt_string_t*`)

You can see string things here:

```c
/**
 * ! Free by ref counting
 */
typedef struct catcrypt_string {
    char* value;
    unsigned int size;
    unsigned int length;
    unsigned int is_alloc_str;
    catcrypt_ref_counted_t ref_counted;
} catcrypt_string_t;

catcrypt_string_t* catcrypt_string_new();
catcrypt_string_t* catcrypt_string_new__n(int length);
catcrypt_string_t catcrypt_string_from_cstr__copy(char* cstr, ssize_t length);
catcrypt_string_t* catcrypt_string_new_from_cstr__copy(char* cstr, ssize_t length);
catcrypt_string_t* catcrypt_string_new_from_binary__copy(char* data, ssize_t length);
catcrypt_string_t catcrypt_string_from_cstr(char* cstr, ssize_t length);
catcrypt_string_t catcrypt_string_from_binary(char* data, ssize_t length);
catcrypt_string_t* catcrypt_string_new_from_cstr(char* cstr, ssize_t length);
void catcrypt_string_free(catcrypt_string_t* string);
void catcrypt_string_set_value(catcrypt_string_t* string, char* value);
void catcrypt_string_set_value__n(catcrypt_string_t* string, char* value, size_t length);
void catcrypt_string_append__cstr__n(catcrypt_string_t* string, char* value, ssize_t length);

bool catcrypt_string_compare(catcrypt_string_t* string, catcrypt_string_t* other);
```

### Reference Counting (`catcrypt_ref_counted_t*`, `catcrypt_ref_t*`)

My reference counting has reference counted type (``catcrypt_ref_counted_t*``) which this library only uses but also it has a reference system too.

```c
typedef void (*catcrypt_ref_free_f_t)(void*);

#define CATCRYPT_REF_COUNTED_INIT(obj, free_f) \
    catcrypt_ref_counted_init(&(obj->ref_counted), (catcrypt_ref_free_f_t) free_f);

#define CATCRYPT_REF_COUNTED_USE(obj) \
    catcrypt_util_verbose("Referencing: %s\n", #obj); \
    \
    catcrypt_ref_counted_use(&(obj->ref_counted));

#define CATCRYPT_REF_COUNTED_LEAVE(obj) \
    catcrypt_util_verbose("Dereferencing: %s\n", #obj); \
    \
    if (obj != NULL) { \
        catcrypt_ref_counted_leave((void **) (&(obj)), &(obj->ref_counted)); \
    }

#define REF_COUNTEDIFY() \
    catcrypt_ref_counted_t ref_counted;
#define CATCRYPT_REF_BY(name) name##_ref
#define CATCRYPT_REF(type, name) \
    type name; \
    catcrypt_ref_t* CATCRYPT_REF_BY(name);
#define CATCRYPT_REF_NEW(path, expr) \
    path = expr; \
    CATCRYPT_REF_BY(path) = catcrypt_ref_new((void *) path, &(path->ref_counted));
#define CATCRYPT_REF_ASSIGN(var, val) \
    catcrypt_ref_assign(&(CATCRYPT_REF_BY(var)), &(CATCRYPT_REF_BY(val))); \
    var = val;
#define CATCRYPT_REF_SET(ref, obj) \
    ref = obj; \
    catcrypt_ref_set(CATCRYPT_REF_BY(ref), (void *) (ref));
#define CATCRYPT_REF_USE(name) catcrypt_ref_use(CATCRYPT_REF_BY(name));
#define CATCRYPT_REF_LEAVE(name) catcrypt_ref_leave(&(CATCRYPT_REF_BY(name)));
#define CATCRYPT_REF_ARG(type, name) type name, catcrypt_ref_t* name##_ref
#define CATCRYPT_REF_PASS(name) catcrypt_ref_new((void *) name, &(name->ref_counted));

typedef struct catcrypt_ref_counted catcrypt_ref_counted_t;
typedef struct catcrypt_ref catcrypt_ref_t;

struct catcrypt_ref_counted {
    int count;
    catcrypt_ref_free_f_t free_f;
};

struct catcrypt_ref {
    int count;
    void* obj;
    catcrypt_ref_counted_t* ref_counted;
};

void catcrypt_ref_counted_init(catcrypt_ref_counted_t* ref_counted, catcrypt_ref_free_f_t free_f);
void catcrypt_ref_counted_use(catcrypt_ref_counted_t* ref_counted);
void catcrypt_ref_counted_leave(void** obj_vp, catcrypt_ref_counted_t* ref_counted);

catcrypt_ref_t* catcrypt_ref_new(void* obj, catcrypt_ref_counted_t* ref_counted);
void catcrypt_ref_free(catcrypt_ref_t* ref);
void catcrypt_ref_use(catcrypt_ref_t* ref);
void catcrypt_ref_leave(catcrypt_ref_t** ref);
void catcrypt_ref_assign(catcrypt_ref_t** dst, catcrypt_ref_t** src);
void catcrypt_ref_set(catcrypt_ref_t* ref, void* obj);
```

## Example

```c
#include <stdio.h>

#include "../../include/rsa.h"

int main() {
    char* data_to_encrypt = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. Sed no sumo stet, est ei quodsi feugait liberavisse, in pro quot facete definitiones. Vivendum intellegat et qui, ei denique consequuntur vix. Offendit eleifend moderatius ex vix, quem odio mazim et qui, purto expetendis cotidieque quo cu, veri persius vituperata ei nec. Partiendo adversarium no mea. Offendit eleifend moderatius ex vix, quem odio mazim et qui, purto expetendis cotidieque quo cu, veri persius vituperata ei nec. Qui gloriatur scribentur et, id velit verear mel, cum no porro debet. Sit fugit nostrum et. Offendit eleifend moderatius ex vix, quem odio mazim et qui, purto expetendis cotidieque quo cu, veri persius vituperata ei nec. Pro ea animal dolores. Scripta periculis ei eam, te pro movet reformidans. Soluta facilisi instructior eam in, ferri oratio ancillae te ius. Vivendum intellegat et qui, ei denique consequuntur vix.";

    printf("Generating key pair...\n");

    catcrypt_string_t* data_to_encrypt_str = catcrypt_string_new_from_cstr(data_to_encrypt, strlen(data_to_encrypt)); CATCRYPT_REF_COUNTED_USE(data_to_encrypt_str);

    catcrypt_rsa_keypair_t* keypair = catcrypt_rsa_keypair_new(); CATCRYPT_REF_COUNTED_USE(keypair);
    
    catcrypt_string_t* pubkey_hex = catcrypt_rsa_key_to_hex(keypair->pubkey); CATCRYPT_REF_COUNTED_USE(pubkey_hex);
    catcrypt_string_t* privkey_hex = catcrypt_rsa_key_to_hex(keypair->privkey); CATCRYPT_REF_COUNTED_USE(privkey_hex);

    catcrypt_rsa_key_t* pubkey_from_hex = catcrypt_rsa_key_from_hex(pubkey_hex); CATCRYPT_REF_COUNTED_USE(pubkey_from_hex);
    catcrypt_rsa_key_t* privkey_from_hex = catcrypt_rsa_key_from_hex(privkey_hex); CATCRYPT_REF_COUNTED_USE(privkey_from_hex);
    catcrypt_string_t* pubkey_from_hex_to_hex = catcrypt_rsa_key_to_hex(pubkey_from_hex); CATCRYPT_REF_COUNTED_USE(pubkey_from_hex_to_hex);
    catcrypt_string_t* privkey_from_hex_to_hex = catcrypt_rsa_key_to_hex(privkey_from_hex); CATCRYPT_REF_COUNTED_USE(privkey_from_hex_to_hex);
    
    catcrypt_rsa_encrypted_t* encrypted = catcrypt_rsa_encrypt(data_to_encrypt_str, pubkey_from_hex); CATCRYPT_REF_COUNTED_USE(encrypted);
    catcrypt_string_t* decrypted = catcrypt_rsa_decrypt(encrypted, privkey_from_hex); CATCRYPT_REF_COUNTED_USE(decrypted);
    printf("Decrypted: %s\n", decrypted->value);
    catcrypt_string_t* signature = catcrypt_rsa_sign(data_to_encrypt_str, keypair->privkey); CATCRYPT_REF_COUNTED_USE(signature);
    catcrypt_string_t* signature_hex = catcrypt_rsa_signature_to_hex(signature); CATCRYPT_REF_COUNTED_USE(signature_hex);
    printf("Signature: %s\n", signature_hex->value);
    catcrypt_string_t* signature_from_hex = catcrypt_rsa_signature_from_hex(signature_hex); CATCRYPT_REF_COUNTED_USE(signature_from_hex);
    
    bool verified = catcrypt_rsa_verify(data_to_encrypt_str, signature_from_hex, keypair->pubkey);
    
    printf("Public Key: %s\n", pubkey_hex->value);
    printf("Private Key: %s\n", privkey_hex->value);
    printf("Public Key From Hex: %s\n", pubkey_from_hex_to_hex->value);
    printf("Private Key From Hex: %s\n", privkey_from_hex_to_hex->value);
    
    printf("Verified: %d\n", verified);

    CATCRYPT_REF_COUNTED_LEAVE(data_to_encrypt_str);
    CATCRYPT_REF_COUNTED_LEAVE(keypair);
    CATCRYPT_REF_COUNTED_LEAVE(pubkey_hex);
    CATCRYPT_REF_COUNTED_LEAVE(privkey_hex);
    CATCRYPT_REF_COUNTED_LEAVE(pubkey_from_hex);
    CATCRYPT_REF_COUNTED_LEAVE(privkey_from_hex);
    CATCRYPT_REF_COUNTED_LEAVE(pubkey_from_hex_to_hex);
    CATCRYPT_REF_COUNTED_LEAVE(privkey_from_hex_to_hex);
    CATCRYPT_REF_COUNTED_LEAVE(encrypted);
    CATCRYPT_REF_COUNTED_LEAVE(decrypted);
    CATCRYPT_REF_COUNTED_LEAVE(signature);
    CATCRYPT_REF_COUNTED_LEAVE(signature_hex);
    CATCRYPT_REF_COUNTED_LEAVE(signature_from_hex);
    
    return 0;
}
```

## What about my dumb hashing algorithm?

Idk.. I had made it for another project [libhash](https://github.com/rohanrhu/libhash) in a coffee break before. According to my tests, it seems pretty oki and safe.

Here my dumb hash32 algorithm:

```c
uint32_t catcrypt_rsa_hash_h32__n(char* data, ssize_t length) {
    uint32_t hash = 0;

    int remaining = 4;
    int prev = 0;

    for (int i=0; (length == -1) ? (i < length): (data[i] != '\0'); i++) {
        remaining--;
        int c = data[i] & 0b01111111;
        uint8_t mask = ((c % 255) << (((((prev % 2) != 0) ? prev: 1) * i * c) % 7));
        *(((unsigned char *)(&hash)) + ((i * c + prev) % 3)) = ((prev % 2) == 0)
                                                             ? mask | prev
                                                             : mask & prev;
        prev = (i * c) % 7;
    }

    for (int i=remaining; i > 0; i--) {
        *(((unsigned char *)(&hash)) + ((4 - i) % 4)) = data[i % ((4 - i) % (4 - remaining))];
    }

    return hash;
}
```

## Definitions

* `CATCRYPT_RSA_PUB_EXPONENT`: The public exponent used in RSA encryption.
* `CATCRYPT_RSA_PRIME_BITS`: The number of bits in the prime numbers used for RSA encryption.
* `CATCRYPT_RSA_PRIME_REPS`: The number of repetitions for the Miller-Rabin primality test.
* `CATCRYPT_RSA_BLOCK_SIZE`: The block size for RSA encryption.

## Structures

* `catcrypt_rsa_key`: Represents an RSA key.
* `catcrypt_rsa_keypair`: Represents a pair of RSA keys (public and private).
* `catcrypt_rsa_encrypted`: Represents encrypted data.

## Functions

### `uint32_t catcrypt_rsa_hash_h32(char* str)`

Hashes a string.

### `uint32_t catcrypt_rsa_hash_h32__n(char* data, ssize_t length)`

Hashes a data of given length.

### `bool catcrypt_rsa_random_seed(unsigned char* seed, size_t size)`

Seeds the random number generator.

### `void catcrypt_rsa_random_prime(mpz_t num)`

Generates a random prime number.

### `catcrypt_rsa_key_t* catcrypt_rsa_key_new()`

Creates a new RSA key.

### `void catcrypt_rsa_key_free(catcrypt_rsa_key_t* key)`

Frees an RSA key.

### `catcrypt_rsa_keypair_t* catcrypt_rsa_keypair_new()`

Creates a new RSA key pair.

### `void catcrypt_rsa_keypair_free(catcrypt_rsa_keypair_t* keypair)`

Frees an RSA key pair.

### `catcrypt_rsa_encrypted_t* catcrypt_rsa_encrypted_new()`

Creates a new encrypted data object.

### `void catcrypt_rsa_encrypted_set_key(catcrypt_rsa_encrypted_t* encrypted, catcrypt_rsa_key_t* key)`

Sets the key for an encrypted data object.

### `void catcrypt_rsa_encrypted_set_data(catcrypt_rsa_encrypted_t* encrypted, catcrypt_string_t* data)`

Sets the data for an encrypted data object.

### `void catcrypt_rsa_encrypted_free(catcrypt_rsa_encrypted_t* encrypted)`

Frees an encrypted data object.

### `catcrypt_rsa_encrypted_t* catcrypt_rsa_encrypt(catcrypt_string_t* data, catcrypt_rsa_key_t* pubkey)`

Encrypts data.

### `catcrypt_string_t* catcrypt_rsa_decrypt(catcrypt_rsa_encrypted_t* encrypted, catcrypt_rsa_key_t* privkey)`

Decrypts data.

### `catcrypt_string_t* catcrypt_rsa_key_to_bin(catcrypt_rsa_key_t* key)`

Converts an RSA key to binary.

### `catcrypt_rsa_key_t* catcrypt_rsa_key_from_bin(catcrypt_string_t* hex)`

Converts binary data to an RSA key.

### `catcrypt_string_t* catcrypt_rsa_key_to_hex(catcrypt_rsa_key_t* key)`

Converts an RSA key to hexadecimal.

### `catcrypt_rsa_key_t* catcrypt_rsa_key_from_hex(catcrypt_string_t* hex)`

Converts hexadecimal data to an RSA key.

### `catcrypt_string_t* catcrypt_rsa_sign(catcrypt_string_t* data, catcrypt_rsa_key_t* privkey)`

Signs data.

### `bool catcrypt_rsa_verify(catcrypt_string_t* data, catcrypt_string_t* signature, catcrypt_rsa_key_t* pubkey)`

Verifies a signature.

### `catcrypt_string_t* catcrypt_rsa_signature_to_hex(catcrypt_string_t* signature_bin)`

Converts a signature to hexadecimal.

### `catcrypt_string_t* catcrypt_rsa_signature_from_hex(catcrypt_string_t* signature_hex)`

Converts hexadecimal data to a signature.

## ❤️ Donate

### Patreon

[![Support me on Patreon](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Fshieldsio-patreon.vercel.app%2Fapi%3Fusername%3DEvrenselKisilik%26type%3Dpatrons&style=for-the-badge)](https://patreon.com/EvrenselKisilik)

### Cryptocurrencies

| Currency | Address                                    |
| -------- | ------------------------------------------ |
| BTC      | bc1qhvlc762kwuzeawedl9a8z0duhs8449nwwc35e2 |
| ETH      | 0x1D99B2a2D85C34d478dD8519792e82B18f861974 |
| USDT     | 0x1D99B2a2D85C34d478dD8519792e82B18f861974 |
| USDC     | 0x1D99B2a2D85C34d478dD8519792e82B18f861974 |
| XMR      | 426nQLFDwpZS64vy6DYdKaHwog3GofyPHFpxvmF6qSQuNg5XJCehv5zPpfh4ff9n5WWfTdKN1Jr29E1XSRuLkjQVJREF7jb |

## License

Copyright (C) 2023, Oğuzhan Eroğlu <rohanrhu2@gmail.com> (https://oguzhaneroglu.com/)

This work is licensed under the terms of the MIT license.  
For a copy, see <https://opensource.org/licenses/MIT>.
