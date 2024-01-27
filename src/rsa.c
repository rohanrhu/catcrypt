/*
 * Catcrypt, simple RSA/PKE for C
 * Copyright (C) 2023, Oğuzhan Eroğlu <meowingcate@gmail.com> (https://meowingcat.io)
 * Licensed under GPLv3 License
 * See LICENSE for more info
 */

/**
 * * Meowing Cat's RSA/PKE implementation
 * 
 * This RSA is safe and secure to use. It uses 2048 bit keys by default.
 * I think prime number generation is safe enough and impossible to break.
 * It uses 65537 for public key exponent.
 * 
 * ! This RSA implementation is not compatible with any other RSA implementation.
 * ! It uses my own format for encrypted data.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include <math.h>
#include <gmp.h>
#include <assert.h>

#include "../include/rsa.h"

#include "../include/util.h"
#include "../include/ref.h"
#include "../include/sugar.h"
#include "../include/string.h"

uint32_t catcrypt_rsa_hash_h32(char* cstr) {
    return catcrypt_rsa_hash_h32__n(cstr, -1);
}

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

bool catcrypt_rsa_random_seed(unsigned char* seed, size_t size) {
    FILE* urandom = fopen("/dev/urandom", "r");
    if (urandom == NULL) {
        return false;
    }
    
    size_t bytes_read = fread(seed, size, 1, urandom);
    if (bytes_read != 1) {
        fclose(urandom);
        return false;
    }

    fclose(urandom);

    return true;
}

void catcrypt_rsa_random_prime(mpz_t num) {
    unsigned char seed[CATCRYPT_RSA_PRIME_BITS / 8];
    
    catcrypt_rsa_random_seed_adds_t adds = 0;
    
    GEN_ADDS:
    
    if (!catcrypt_rsa_random_seed((unsigned char *) &adds, sizeof(adds))) {
        fprintf(stderr, "catcrypt_rsa_random_prime(): Failed to generate random seed.\n");
        exit(1);
    }
    adds &= CATCRYPT_RSA_RANDOM_SEED_ADDS_MASK;

    if (adds == 0) {
        goto GEN_ADDS;
    }
    
    mpz_t to_add;

    ADD:

    mpz_init(to_add);
    if (!catcrypt_rsa_random_seed(seed, CATCRYPT_RSA_PRIME_BITS / 8)) {
        fprintf(stderr, "catcrypt_rsa_random_prime(): Failed to generate random seed.\n");
        exit(1);
    }
    mpz_import(to_add, CATCRYPT_RSA_PRIME_BITS / 8, 1, sizeof(seed[0]), 0, 0, seed);

    if (adds > 0) {
        mpz_add(num, num, to_add);
        adds--;
        goto ADD;
    }

    mpz_setbit(num, 0);
    
    while (!mpz_probab_prime_p(num, CATCRYPT_RSA_PRIME_REPS)) {
        mpz_add_ui(num, num, 2);
    }
}

catcrypt_rsa_key_t* catcrypt_rsa_key_new() {
    catcrypt_rsa_key_t* key = malloc(sizeof(catcrypt_rsa_key_t));
    CATCRYPT_REF_COUNTED_INIT(key, catcrypt_rsa_key_free);
    CATCRYPT_REF_COUNTED_USE(key);
    
    mpz_init(key->e);
    mpz_init(key->n);

    return key;
}

void catcrypt_rsa_key_free(catcrypt_rsa_key_t* key) {
    mpz_clear(key->e);
    mpz_clear(key->n);
    free(key);
}

catcrypt_rsa_keypair_t* catcrypt_rsa_keypair_new() {
    catcrypt_rsa_keypair_t* keypair = malloc(sizeof(catcrypt_rsa_keypair_t));
    CATCRYPT_REF_COUNTED_INIT(keypair, catcrypt_rsa_keypair_free);
    CATCRYPT_REF_COUNTED_USE(keypair);
    
    keypair->pubkey = catcrypt_rsa_key_new();
    CATCRYPT_REF_COUNTED_USE(keypair->pubkey);
    keypair->privkey = catcrypt_rsa_key_new();
    CATCRYPT_REF_COUNTED_USE(keypair->privkey);
    
    mpz_init(keypair->pubkey->n);
    mpz_init(keypair->pubkey->e);
    
    mpz_init(keypair->privkey->n);
    mpz_init(keypair->privkey->e);

    mpz_t p;
    mpz_init(p);
    mpz_t q;
    mpz_init(q);
    mpz_t n;
    mpz_init(n);
    mpz_t phi;
    mpz_init(phi);
    mpz_t e;
    mpz_init(e);
    mpz_t d;
    mpz_init(d);
    mpz_t pmo;
    mpz_init(pmo);
    mpz_t qmo;
    mpz_init(qmo);

    mpz_set_ui(e, CATCRYPT_RSA_PUB_EXPONENT);

    catcrypt_rsa_random_prime(p);
    catcrypt_rsa_random_prime(q);

    mpz_mul(n, p, q);
    
    mpz_set(pmo, p);
    mpz_set(qmo, q);
    mpz_sub_ui(pmo, p, 1);
    mpz_sub_ui(qmo, q, 1);
    mpz_mul(phi, pmo, qmo);

    CATCRYPT_UTIL_ASSERT(mpz_invert(d, e, phi));

    mpz_set(keypair->pubkey->e, e);
    mpz_set(keypair->pubkey->n, n);
    
    mpz_set(keypair->privkey->e, d);
    mpz_set(keypair->privkey->n, n);

    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(n);
    mpz_clear(phi);
    mpz_clear(e);
    mpz_clear(d);

    return keypair;
}

void catcrypt_rsa_keypair_free(catcrypt_rsa_keypair_t* keypair) {
    CATCRYPT_REF_COUNTED_LEAVE(keypair->pubkey);
    CATCRYPT_REF_COUNTED_LEAVE(keypair->privkey);
    free(keypair);
}

catcrypt_rsa_encrypted_t* catcrypt_rsa_encrypted_new() {
    catcrypt_rsa_encrypted_t* encrypted = malloc(sizeof(catcrypt_rsa_encrypted_t));
    CATCRYPT_REF_COUNTED_INIT(encrypted, catcrypt_rsa_encrypted_free);
    
    encrypted->data = NULL;
    encrypted->key = NULL;

    return encrypted;
}

void catcrypt_rsa_encrypted_set_key(catcrypt_rsa_encrypted_t* encrypted, catcrypt_rsa_key_t* key) {
    CATCRYPT_REF_COUNTED_LEAVE(encrypted->key);
    CATCRYPT_REF_COUNTED_USE(key);
    encrypted->key = key;
}

void catcrypt_rsa_encrypted_set_data(catcrypt_rsa_encrypted_t* encrypted, catcrypt_string_t* data) {
    CATCRYPT_REF_COUNTED_LEAVE(encrypted->data);
    CATCRYPT_REF_COUNTED_USE(data);
    encrypted->data = data;
}

void catcrypt_rsa_encrypted_free(catcrypt_rsa_encrypted_t* encrypted) {
    CATCRYPT_REF_COUNTED_LEAVE(encrypted->data);
    CATCRYPT_REF_COUNTED_LEAVE(encrypted->key);
    free(encrypted);
}

catcrypt_rsa_encrypted_t* catcrypt_rsa_encrypt(catcrypt_string_t* data, catcrypt_rsa_key_t* pubkey) {
    CATCRYPT_REF_COUNTED_USE(data);
    CATCRYPT_REF_COUNTED_USE(pubkey);
    
    catcrypt_rsa_encrypted_t* encrypted = catcrypt_rsa_encrypted_new();
    catcrypt_rsa_encrypted_set_data(encrypted, catcrypt_string_new());
    catcrypt_rsa_encrypted_set_key(encrypted, pubkey);
    
    mpz_t m;
    mpz_init(m);
    mpz_t c;
    mpz_init(c);
    
    int pages = data->length / CATCRYPT_RSA_BLOCK_SIZE;
    if (data->length % CATCRYPT_RSA_BLOCK_SIZE != 0) {
        pages++;
    }

    int page_size;
    int page_offset = 0;
    char* page;

    for (int i = 0; i < pages; i++) {
        page_size = (i == (pages-1)) ? (data->length % CATCRYPT_RSA_BLOCK_SIZE): CATCRYPT_RSA_BLOCK_SIZE;
        page = data->value + page_offset;
        page_offset += page_size;

        mpz_import(m, page_size, CATCRYPT_MPZ_ORDER, 1, CATCRYPT_MPZ_ENDIAN, 0, page);
        mpz_powm(c, m, pubkey->e, pubkey->n);

        size_t bignum_size = 0;
        char* c_str = mpz_export(NULL, &bignum_size, CATCRYPT_MPZ_ORDER, 1, CATCRYPT_MPZ_ENDIAN, 0, c);
        catcrypt_string_append__cstr__n(encrypted->data, (char *) (&bignum_size), sizeof(bignum_size));
        catcrypt_string_append__cstr__n(encrypted->data, c_str, bignum_size);
        free(c_str);
    }

    CATCRYPT_REF_COUNTED_LEAVE(data);
    CATCRYPT_REF_COUNTED_LEAVE(pubkey);

    return encrypted; 
}

catcrypt_string_t* catcrypt_rsa_decrypt(catcrypt_rsa_encrypted_t* encrypted, catcrypt_rsa_key_t* privkey) {
    CATCRYPT_REF_COUNTED_USE(encrypted);
    CATCRYPT_REF_COUNTED_USE(privkey);
    
    catcrypt_string_t* decrypted = catcrypt_string_new();
    mpz_t c;
    mpz_init(c);
    mpz_t m;
    mpz_init(m);

    for (int index = 0; index < encrypted->data->length;) {
        size_t to_decrypt = *((size_t *) (encrypted->data->value + index));

        char* block = encrypted->data->value + index + sizeof(size_t);

        mpz_import(c, to_decrypt, CATCRYPT_MPZ_ORDER, 1, CATCRYPT_MPZ_ENDIAN, 0, block);
        mpz_powm(m, c, privkey->e, privkey->n);

        size_t bignum_size = 0;
        char* c_str = mpz_export(NULL, &bignum_size, CATCRYPT_MPZ_ORDER, 1, CATCRYPT_MPZ_ENDIAN, 0, m);
        catcrypt_string_append__cstr__n(decrypted, c_str, bignum_size);
        free(c_str);

        index += sizeof(size_t);
        index += to_decrypt;
    }

    CATCRYPT_REF_COUNTED_LEAVE(encrypted);
    CATCRYPT_REF_COUNTED_LEAVE(privkey);

    return decrypted;
}

catcrypt_string_t* catcrypt_rsa_sign(catcrypt_string_t* data, catcrypt_rsa_key_t* privkey) {
    CATCRYPT_REF_COUNTED_USE(data);
    CATCRYPT_REF_COUNTED_USE(privkey);

    uint32_t hash = catcrypt_rsa_hash_h32__n(data->value, data->length);
    catcrypt_string_t* hash_str = catcrypt_string_new_from_binary__copy((char *) &hash, sizeof(hash));
    CATCRYPT_REF_COUNTED_USE(hash_str);
    catcrypt_rsa_encrypted_t* encrypted = catcrypt_rsa_encrypt(hash_str, privkey);
    CATCRYPT_REF_COUNTED_USE(encrypted);

    CATCRYPT_REF_COUNTED_LEAVE(data);
    CATCRYPT_REF_COUNTED_LEAVE(privkey);

    catcrypt_string_t* encrypted_data = encrypted->data;

    encrypted_data->ref_counted.count++;
    CATCRYPT_REF_COUNTED_LEAVE(encrypted);
    encrypted_data->ref_counted.count--;
    
    return encrypted_data;
}

bool catcrypt_rsa_verify(catcrypt_string_t* data, catcrypt_string_t* signature, catcrypt_rsa_key_t* pubkey) {
    CATCRYPT_REF_COUNTED_USE(data);
    CATCRYPT_REF_COUNTED_USE(signature);
    CATCRYPT_REF_COUNTED_USE(pubkey);

    catcrypt_rsa_encrypted_t* encrypted = catcrypt_rsa_encrypted_new();
    catcrypt_rsa_encrypted_set_data(encrypted, signature);
    catcrypt_string_t* decrypted = catcrypt_rsa_decrypt(encrypted, pubkey);
    uint32_t hash = catcrypt_rsa_hash_h32__n(data->value, data->length);
    catcrypt_string_t* hash_str = catcrypt_string_new_from_binary__copy((char *) &hash, sizeof(hash));
    CATCRYPT_REF_COUNTED_USE(hash_str);

    bool result = catcrypt_string_compare(decrypted, hash_str);

    CATCRYPT_REF_COUNTED_LEAVE(data);
    CATCRYPT_REF_COUNTED_LEAVE(signature);
    CATCRYPT_REF_COUNTED_LEAVE(pubkey);

    return result;
}


catcrypt_string_t* catcrypt_rsa_signature_to_hex(catcrypt_string_t* signature_bin) {
    CATCRYPT_REF_COUNTED_USE(signature_bin);

    char* hex = malloc(signature_bin->length * 2 + 1);
    for (size_t i = 0; i < signature_bin->length; i++) {
        sprintf(hex + i * 2, "%02x", (unsigned char)signature_bin->value[i]);
    }
    hex[signature_bin->length * 2] = '\0';

    catcrypt_string_t* signature_hex = catcrypt_string_new_from_cstr__copy(hex, signature_bin->length * 2);
    free(hex);

    CATCRYPT_REF_COUNTED_LEAVE(signature_bin);

    return signature_hex;
}

catcrypt_string_t* catcrypt_rsa_signature_from_hex(catcrypt_string_t* signature_hex) {
    CATCRYPT_REF_COUNTED_USE(signature_hex);

    char* signature = malloc(signature_hex->length / 2);
    for (size_t i = 0; i < signature_hex->length / 2; i++) {
        unsigned int temp;
        sscanf(signature_hex->value + i * 2, "%02x", &temp);
        signature[i] = (char)temp;
    }

    catcrypt_string_t* signature_bin = catcrypt_string_new_from_cstr__copy(signature, signature_hex->length / 2);
    free(signature);

    CATCRYPT_REF_COUNTED_LEAVE(signature_hex);

    return signature_bin;
}

catcrypt_string_t* catcrypt_rsa_key_to_bin(catcrypt_rsa_key_t* key) {
    CATCRYPT_REF_COUNTED_USE(key);

    size_t marshalled_size = 0;
    
    size_t exponent_size = 0;
    char* exponent = mpz_export(NULL, &exponent_size, CATCRYPT_MPZ_ORDER, 1, CATCRYPT_MPZ_ENDIAN, 0, key->e);
    marshalled_size += exponent_size * 2;

    size_t modulus_size = 0;
    char* modulus = mpz_export(NULL, &modulus_size, CATCRYPT_MPZ_ORDER, 1, CATCRYPT_MPZ_ENDIAN, 0, key->n);
    marshalled_size += modulus_size * 2;
    
    catcrypt_string_t* key_hex = catcrypt_string_new();
    catcrypt_string_append__cstr__n(key_hex, (char *) &exponent_size, sizeof(exponent_size));
    catcrypt_string_append__cstr__n(key_hex, (char *) &modulus_size, sizeof(modulus_size));
    catcrypt_string_append__cstr__n(key_hex, exponent, exponent_size);
    catcrypt_string_append__cstr__n(key_hex, modulus, modulus_size);

    free(exponent);
    free(modulus);
    
    CATCRYPT_REF_COUNTED_LEAVE(key);

    return key_hex;
}

catcrypt_rsa_key_t* catcrypt_rsa_key_from_bin(catcrypt_string_t* hex) {
    CATCRYPT_REF_COUNTED_USE(hex);

    size_t exponent_size = *((size_t *) hex->value);
    size_t modulus_size = *((size_t *) (hex->value + sizeof(exponent_size)));

    char* exponent = hex->value + sizeof(exponent_size) + sizeof(modulus_size);
    char* modulus = exponent + exponent_size;

    catcrypt_rsa_key_t* key = catcrypt_rsa_key_new();
    mpz_import(key->e, exponent_size, CATCRYPT_MPZ_ORDER, 1, CATCRYPT_MPZ_ENDIAN, 0, exponent);
    mpz_import(key->n, modulus_size, CATCRYPT_MPZ_ORDER, 1, CATCRYPT_MPZ_ENDIAN, 0, modulus);

    CATCRYPT_REF_COUNTED_LEAVE(hex);

    return key;
}

catcrypt_string_t* catcrypt_rsa_key_to_hex(catcrypt_rsa_key_t* key) {
    CATCRYPT_REF_COUNTED_USE(key);

    catcrypt_string_t* key_bin = catcrypt_rsa_key_to_bin(key);

    char* key_hex = malloc(key_bin->length * 2 + 1);
    for (size_t i = 0; i < key_bin->length; i++) {
        sprintf(key_hex + i * 2, "%02x", (unsigned char)key_bin->value[i]);
    }
    key_hex[key_bin->length * 2] = '\0';

    catcrypt_string_t* key_hex_str = catcrypt_string_new_from_cstr__copy(key_hex, key_bin->length * 2);

    free(key_hex);
    CATCRYPT_REF_COUNTED_LEAVE(key);

    return key_hex_str;
}

catcrypt_rsa_key_t* catcrypt_rsa_key_from_hex(catcrypt_string_t* hex) {
    CATCRYPT_REF_COUNTED_USE(hex);

    char* key_bin = malloc(hex->length / 2);
    for (size_t i = 0; i < hex->length / 2; i++) {
        unsigned int temp;
        sscanf(hex->value + i * 2, "%02x", &temp);
        key_bin[i] = (char)temp;
    }

    catcrypt_string_t* key_bin_str = catcrypt_string_new_from_cstr__copy(key_bin, hex->length / 2);
    key_bin_str->is_alloc_str = true;
    catcrypt_rsa_key_t* key_hex = catcrypt_rsa_key_from_bin(key_bin_str);

    free(key_bin);
    CATCRYPT_REF_COUNTED_LEAVE(hex);

    return key_hex;
}