#pragma once
#include <oqs/oqs.h>
#include <sodium.h>
#include <vector>
#include <stdexcept>
#include <iostream>
#include <cstring>

namespace VoidGate {

class CryptoEngine {
    const char* kem_alg = OQS_KEM_alg_kyber_512;
    OQS_KEM* kem;
    std::vector<uint8_t> session_key;

public:
    CryptoEngine() {
        if (sodium_init() < 0) throw std::runtime_error("Libsodium init failed");
        OQS_init();
        kem = OQS_KEM_new(kem_alg);
        if (!kem) throw std::runtime_error("Kyber-512 algorithm not available");
    }

    ~CryptoEngine() {
        if (kem) OQS_KEM_free(kem);
        OQS_destroy();
    }

    // --- POST-QUANTUM KEY EXCHANGE ---

    // [SERVER] Генерация пары (Public/Secret)
    void generate_keypair(std::vector<uint8_t>& public_key, std::vector<uint8_t>& secret_key) {
        public_key.resize(kem->length_public_key);
        secret_key.resize(kem->length_secret_key);
        if (OQS_KEM_keypair(kem, public_key.data(), secret_key.data()) != OQS_SUCCESS)
            throw std::runtime_error("KEM Keypair generation failed");

        std::cout << "[CRYPTO] Generated Kyber-512 Keypair." << std::endl;
    }

    // [CLIENT] Инкапсуляция (Создает Shared Secret + Ciphertext)
    void encapsulate(const std::vector<uint8_t>& public_key, std::vector<uint8_t>& ciphertext) {
        ciphertext.resize(kem->length_ciphertext);
        std::vector<uint8_t> shared_secret(kem->length_shared_secret);

        if (OQS_KEM_encaps(kem, ciphertext.data(), shared_secret.data(), public_key.data()) != OQS_SUCCESS)
            throw std::runtime_error("KEM Encapsulation failed");

        derive_session_key(shared_secret);
        std::cout << "[CRYPTO] Quantum Secret Encapsulated." << std::endl;
    }

    // [SERVER] Декапсуляция (Извлекает Shared Secret из Ciphertext)
    void decapsulate(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& secret_key) {
        std::vector<uint8_t> shared_secret(kem->length_shared_secret);

        if (OQS_KEM_decaps(kem, shared_secret.data(), ciphertext.data(), secret_key.data()) != OQS_SUCCESS)
            throw std::runtime_error("KEM Decapsulation failed");

        derive_session_key(shared_secret);
        std::cout << "[CRYPTO] Quantum Secret Decapsulated successfully." << std::endl;
    }

    // --- SYMMETRIC ENCRYPTION (ChaCha20-Poly1305) ---

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext, uint64_t nonce_counter) {
        if (session_key.empty()) return {}; // Ключ не установлен

        std::vector<uint8_t> nonce(crypto_aead_chacha20poly1305_ietf_NPUBBYTES, 0);
        memcpy(nonce.data(), &nonce_counter, sizeof(nonce_counter));

        std::vector<uint8_t> ciphertext(plaintext.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
        unsigned long long clen;

        crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext.data(), &clen,
            plaintext.data(), plaintext.size(),
            NULL, 0, NULL, nonce.data(), session_key.data()
        );
        ciphertext.resize(clen);
        return ciphertext;
    }

    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext, uint64_t nonce_counter) {
        if (session_key.empty()) return {};

        std::vector<uint8_t> nonce(crypto_aead_chacha20poly1305_ietf_NPUBBYTES, 0);
        memcpy(nonce.data(), &nonce_counter, sizeof(nonce_counter));

        std::vector<uint8_t> plaintext(ciphertext.size() - crypto_aead_chacha20poly1305_ietf_ABYTES);
        unsigned long long plen;

        if (crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext.data(), &plen,
            NULL,
            ciphertext.data(), ciphertext.size(),
            NULL, 0, nonce.data(), session_key.data()) != 0) {
            return {}; // Ошибка проверки MAC или дешифровки
        }
        plaintext.resize(plen);
        return plaintext;
    }

    // Хак для Демо-режима: Установить ключ вручную (без сетевого обмена)
    void debug_set_fake_key() {
        std::vector<uint8_t> fake(32, 0xCC);
        derive_session_key(fake);
    }

private:
    void derive_session_key(const std::vector<uint8_t>& raw_secret) {
        session_key.resize(crypto_aead_chacha20poly1305_ietf_KEYBYTES);
        crypto_generichash(session_key.data(), session_key.size(),
                           raw_secret.data(), raw_secret.size(),
                           NULL, 0);
    }
};

}
