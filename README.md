# 🛡️ VOID-GATE: Post-Quantum VPN Tunnel

> **Secure. Fast. Future-Proof.**
> **Безопасный. Быстрый. Готовый к будущему.**

[![C++20](https://img.shields.io/badge/std-c%2B%2B20-blue.svg)](https://isocpp.org/)
[![Quantum Safe](https://img.shields.io/badge/Encryption-Kyber512-purple)](https://openquantumsafe.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20WSL-lightgrey)]()

---

## 🇬🇧 English Description

**Void-Gate** is a high-performance userspace VPN implementing **Post-Quantum Cryptography (PQC)** to secure data against future quantum computing threats.

Unlike traditional VPNs (OpenVPN, WireGuard) that rely on classical Diffie-Hellman or ECC key exchange, Void-Gate utilizes **NIST-standardized Kyber-512 (ML-KEM)** for key encapsulation. This ensures that your traffic cannot be decrypted even by a powerful quantum computer in the future ("Harvest Now, Decrypt Later" protection).

### 🔥 Key Features
*   **Quantum-Resistant Handshake:** Uses `liboqs` to implement **Kyber-512**, a lattice-based KEM algorithm selected by NIST.
*   **High-Speed Encryption:** Uses **ChaCha20-Poly1305** (IETF) for symmetric traffic encryption — faster than AES on mobile/IoT devices without hardware acceleration.
*   **Zero-Copy Networking:** Direct interaction with Linux Kernel via `TUN/TAP` interface (`void0` device).
*   **Anti-Replay Protection:** Strict 64-bit nonce enforcement prevents replay attacks.

### 🛠️ Architecture
| Component | Technology | Purpose |
| :--- | :--- | :--- |
| **KEM** | `Kyber-512` | Quantum-safe key exchange |
| **AEAD** | `ChaCha20-Poly1305` | Authenticated encryption (Confidentiality + Integrity) |
| **Interface** | `TUN (Layer 3)` | IP Tunneling |
| **Hash** | `BLAKE2b` | Key Derivation Function (KDF) |

---

## 🇷🇺 Описание на Русском

**Void-Gate** — это высокопроизводительный VPN-туннель нового поколения, использующий **постквантовую криптографию** для защиты данных от угроз квантовых вычислений.

В отличие от классических VPN (OpenVPN, IPsec), которые используют RSA или эллиптические кривые (уязвимые для алгоритма Шора), Void-Gate использует алгоритм **Kyber-512** (стандарт NIST). Это защищает трафик от атак типа "Сохрани сейчас, расшифруй потом", когда злоумышленники записывают шифрованный трафик в надежде расшифровать его через 10 лет на квантовом компьютере.

### 🔥 Ключевые особенности
*   **Постквантовое рукопожатие:** Реализация алгоритма **Kyber-512** (ML-KEM) через библиотеку `liboqs`.
*   **Скоростное шифрование:** Использование потокового шифра **ChaCha20-Poly1305**. Работает быстрее AES на процессорах без аппаратного ускорения.
*   **Работа с ядром Linux:** Прямое взаимодействие с интерфейсом `TUN` для создания виртуальной сетевой карты `void0`.
*   **Защита от повторов:** Механизм проверки уникальных nonce (меток) пакетов для защиты от Replay-атак.

### 🛠️ Технологический стек
| Компонент | Технология | Назначение |
| :--- | :--- | :--- |
| **Обмен ключами** | `Kyber-512` | Защита от квантовых компьютеров |
| **Шифрование** | `ChaCha20-Poly1305` | Конфиденциальность и целостность данных |
| **Сеть** | `TUN (Layer 3)` | IP-туннелирование |
| **Хеширование** | `BLAKE2b` | Генерация сессионных ключей |

---

## 🚀 Installation & Build / Установка и сборка

### 1. Dependencies / Зависимости
Requires Linux (Ubuntu/Debian/Kali) or WSL2. / Требуется Linux или WSL2.

Install tools
sudo apt update
sudo apt install build-essential cmake libsodium-dev ninja-build git

Build liboqs (Post-Quantum Library)
git clone -b main https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -GNinja -DOQS_USE_OPENSSL=OFF ..
ninja && sudo ninja install && sudo ldconfig

### 2. Build Void-Gate / Сборка проекта
Clone repository
git clone https://github.com/YOUR_USERNAME/void-gate.git
cd void-gate

Compile
mkdir build && cd build
cmake -G Ninja ..
ninja

---

## 💻 Usage / Использование

**Note:** Root privileges (`sudo`) are required to manage network interfaces.
**Важно:** Для создания сетевых интерфейсов требуются права `root` (`sudo`).

### 1. Server Side / Сервер
Starts the VPN server on port 5555. Creates `void0` interface.
Запускает сервер на порту 5555. Создает интерфейс `void0`.
sudo ./voidgate server 5555

### 2. Client Side / Клиент
Connects to the server. Creates `void1` interface.
Подключается к серверу. Создает интерфейс `void1`.
sudo ./voidgate client <SERVER_IP> 5555

*(For local test use `127.0.0.1` / Для теста локально используйте `127.0.0.1`)*

### 3. Verify / Проверка
Open a new terminal and ping the secure tunnel address.
Откройте новый терминал и пропингуйте адрес внутри туннеля.
ping 10.99.0.1

---

## 📊 Demo Output / Пример работы

=== [ INITIALIZING QUANTUM HANDSHAKE ] ===
[✓] NIST Kyber-512 Keypair Generated (800 bytes)
[✓] Post-Quantum Shared Secret Established
=== [ QUANTUM TUNNEL READY ] ===

[*] Listening for traffic...
[STATUS] TX: 12.4MB | RX: 45.1MB | Secured by Kyber-512
---

### ⚠️ Disclaimer
This is a Proof-of-Concept (PoC) for educational purposes. / Это учебный прототип (PoC) для демонстрации технологий.


**License:** MIT
