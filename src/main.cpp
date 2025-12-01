#include <iostream>
#include <string>
#include "Core.hpp"

void print_banner() {
    std::cout << R"(
 __      __   _    _        _____       _
 \ \    / /  (_)  | |      / ____|     | |
  \ \  / /__  _ __| |_____| |  __  __ _| |_ ___
   \ \/ / _ \| |/ _` |____| | |_ |/ _` | __/ _ \
    \  / (_) | | (_| |    | |__| | (_| | ||  __/
     \/ \___/|_|\__,_|     \_____|\__,_|\__\___|

    Post-Quantum VPN Tunnel [Kyber-512 | ChaCha20]
    Build: v1.0 (Hardcore Edition)
    )" << std::endl;
}

int main(int argc, char* argv[]) {
    print_banner();

    if (argc < 3) {
        std::cout << "Usage:\n";
        std::cout << "  Server: sudo ./voidgate server <port>\n";
        std::cout << "  Client: sudo ./voidgate client <server_ip> <port>\n";
        return 1;
    }

    std::string mode = argv[1];
    int port = 5555;
    std::string ip = "127.0.0.1";

    try {
        bool is_server = (mode == "server");
        if (is_server) {
            port = std::stoi(argv[2]);
        } else {
            ip = argv[2];
            port = std::stoi(argv[3]);
        }

        VoidGate::TunnelCore vpn(is_server, ip, port);
        vpn.perform_handshake_simulation();
        vpn.run();

    } catch (const std::exception& e) {
        std::cerr << "[CRITICAL ERROR] " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
