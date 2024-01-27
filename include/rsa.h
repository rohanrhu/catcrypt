/*
 * Catcrypt, simple RSA/PKE for C
 * Copyright (C) 2023, Oğuzhan Eroğlu <meowingcate@gmail.com> (https://meowingcat.io)
 * Licensed under GPLv3 License
 * See LICENSE for more info
 */

#pragma once

#include <stdbool.h>
#include <gmp.h>

#include "ref.h"
#include "sugar.h"
#include "string.h"

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