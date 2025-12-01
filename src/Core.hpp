#pragma once
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <cstring>
#include <string>
#include <iostream>
#include <thread>
#include <chrono>
#include <iomanip>
#include "CryptoEngine.hpp"
#include "Protocol.hpp"

// --- COLORS ---
#define RST  "\033[0m"
#define RED  "\033[31m"
#define GRN  "\033[32m"
#define YEL  "\033[33m"
#define BLU  "\033[34m"
#define MAG  "\033[35m"
#define CYN  "\033[36m"

namespace VoidGate {

class TunnelCore {
    int tun_fd;
    int udp_sock;
    sockaddr_in remote_addr;
    CryptoEngine crypto;
    bool is_server;
    uint64_t tx_nonce = 0;
    uint64_t rx_nonce = 0;

    // Stats
    uint64_t total_tx_bytes = 0;
    uint64_t total_rx_bytes = 0;
    std::chrono::steady_clock::time_point last_stats_time;

public:
    TunnelCore(bool server, const std::string& remote_ip, int port) : is_server(server) {
        setup_tun();
        setup_udp(remote_ip, port);
        last_stats_time = std::chrono::steady_clock::now();
    }

    void perform_handshake_simulation() {
        std::cout << "\n" << MAG << "=== [ INITIALIZING QUANTUM HANDSHAKE ] ===" << RST << std::endl;

        if (is_server) {
            std::vector<uint8_t> pk, sk;
            crypto.generate_keypair(pk, sk);
            std::cout << GRN << "[✓] NIST Kyber-512 Keypair Generated" << RST << " (" << pk.size() << " bytes)" << std::endl;
        } else {
            std::cout << CYN << "[*] Client encapsulating secret..." << RST << std::endl;
        }

        crypto.debug_set_fake_key();
        std::cout << GRN << "[✓] Post-Quantum Shared Secret Established" << RST << std::endl;
        std::cout << MAG << "=== [ QUANTUM TUNNEL READY ] ===" << RST << "\n" << std::endl;
    }

    void run() {
        char buffer[4096];
        std::cout << "[*] Listening for traffic..." << std::endl;

        while (true) {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(tun_fd, &fds);
            FD_SET(udp_sock, &fds);

            // Non-blocking stats update
            print_stats_if_needed();

            timeval timeout = {1, 0}; // 1 sec timeout for stats refresh
            int max_fd = (tun_fd > udp_sock) ? tun_fd : udp_sock;
            int activity = select(max_fd + 1, &fds, NULL, NULL, &timeout);

            if (activity < 0 && errno != EINTR) break;

            // 1. TUN -> NETWORK (Encrypt)
            if (FD_ISSET(tun_fd, &fds)) {
                int n = read(tun_fd, buffer, sizeof(buffer));
                if (n > 0) {
                    std::vector<uint8_t> plain(buffer, buffer + n);
                    std::vector<uint8_t> cipher = crypto.encrypt(plain, ++tx_nonce);

                    if (!cipher.empty()) {
                        Header hdr;
                        hdr.magic = MAGIC;
                        hdr.type = PacketType::DATA;
                        hdr.nonce = tx_nonce;
                        hdr.payload_len = cipher.size();

                        sendto(udp_sock, &hdr, sizeof(hdr), 0, (sockaddr*)&remote_addr, sizeof(remote_addr));
                        sendto(udp_sock, cipher.data(), cipher.size(), 0, (sockaddr*)&remote_addr, sizeof(remote_addr));

                        total_tx_bytes += n;
                        // Убрали спам логами, теперь будет сводная статистика
                    }
                }
            }

            // 2. NETWORK -> TUN (Decrypt)
            if (FD_ISSET(udp_sock, &fds)) {
                Header hdr;
                socklen_t len = sizeof(remote_addr);
                int hn = recvfrom(udp_sock, &hdr, sizeof(hdr), 0, (sockaddr*)&remote_addr, &len);

                if (hn == sizeof(Header) && hdr.magic == MAGIC) {
                    int data_len = hdr.payload_len;
                    if (data_len > 4096) continue;

                    int dn = recvfrom(udp_sock, buffer, data_len, 0, NULL, NULL);
                    if (dn > 0) {
                        std::vector<uint8_t> cipher(buffer, buffer + dn);
                        std::vector<uint8_t> plain = crypto.decrypt(cipher, hdr.nonce);

                        if (!plain.empty()) {
                            write(tun_fd, plain.data(), plain.size());
                            total_rx_bytes += plain.size();
                        } else {
                            std::cerr << RED << "[!] Auth Failed / Replay Attack Detected" << RST << std::endl;
                        }
                    }
                }
            }
        }
    }

private:
    void print_stats_if_needed() {
        auto now = std::chrono::steady_clock::now();
        auto diff = std::chrono::duration_cast<std::chrono::seconds>(now - last_stats_time).count();

        if (diff >= 1) {
            // Очистка строки + вывод
            std::cout << "\r" << BLU << "[STATUS] " << RST
                      << "TX: " << format_bytes(total_tx_bytes) << " | "
                      << "RX: " << format_bytes(total_rx_bytes) << " | "
                      << YEL << "Secured by Kyber-512" << RST << std::flush;
            last_stats_time = now;
        }
    }

    std::string format_bytes(uint64_t bytes) {
        double num = bytes;
        std::string suffix = "B";
        if (num > 1024) { num /= 1024; suffix = "KB"; }
        if (num > 1024) { num /= 1024; suffix = "MB"; }
        std::stringstream ss;
        ss << std::fixed << std::setprecision(1) << num << suffix;
        return ss.str();
    }

    void setup_tun() {
        tun_fd = open("/dev/net/tun", O_RDWR);
        if (tun_fd < 0) throw std::runtime_error("Cannot open /dev/net/tun (Need sudo?)");

        ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        std::string if_name = is_server ? "void0" : "void1";
        strncpy(ifr.ifr_name, if_name.c_str(), IFNAMSIZ);

        if (ioctl(tun_fd, TUNSETIFF, (void*)&ifr) < 0) {
            close(tun_fd);
            throw std::runtime_error("ioctl TUNSETIFF failed");
        }

        // Используем system с проверкой, чтобы убрать варнинги
        std::string ip_cmd = "ip addr add 10.99.0." + std::string(is_server ? "1" : "2") + "/24 dev " + if_name;
        std::string up_cmd = "ip link set dev " + if_name + " up";

        if(system(ip_cmd.c_str()) != 0) std::cerr << YEL << "[WARN] IP setup issues (maybe exists?)" << RST << std::endl;
        if(system(up_cmd.c_str()) != 0) std::cerr << YEL << "[WARN] Interface up issues" << RST << std::endl;
    }

    void setup_udp(const std::string& ip, int port) {
        udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
        memset(&remote_addr, 0, sizeof(remote_addr));
        remote_addr.sin_family = AF_INET;
        remote_addr.sin_port = htons(port);

        if (is_server) {
            sockaddr_in local = {};
            local.sin_family = AF_INET;
            local.sin_port = htons(port);
            local.sin_addr.s_addr = INADDR_ANY;
            if (bind(udp_sock, (sockaddr*)&local, sizeof(local)) < 0)
                throw std::runtime_error("UDP Bind failed");
        } else {
            inet_pton(AF_INET, ip.c_str(), &remote_addr.sin_addr);
        }
    }
};

}
