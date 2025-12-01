#pragma once
#include <cstdint>

namespace VoidGate {
    // Магическая метка пакета (V G A T)
    constexpr uint32_t MAGIC = 0x56474154;

    enum class PacketType : uint8_t {
        HANDSHAKE_INIT = 0x01,
        HANDSHAKE_RESP = 0x02,
        DATA           = 0x03,
        KEEPALIVE      = 0x04
    };

#pragma pack(push, 1)
    struct Header {
        uint32_t magic;        // 4 байта
        PacketType type;       // 1 байт
        uint64_t nonce;        // 8 байт (защита от повторов + IV)
        uint16_t payload_len;  // 2 байта
        uint8_t  auth_tag[16]; // 16 байт (Poly1305 MAC)
    };
#pragma pack(pop)
    // Итого заголовок: 31 байт
}
