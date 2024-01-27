/*
 * Catcrypt, simple RSA/PKE for C
 * Copyright (C) 2023, Oğuzhan Eroğlu <meowingcate@gmail.com> (https://meowingcat.io)
 * Licensed under GPLv3 License
 * See LICENSE for more info
 */

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