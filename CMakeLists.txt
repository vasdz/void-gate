cmake_minimum_required(VERSION 3.20)
project(VoidGate)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_options(-O3 -march=native -Wall -pthread)

# --- ПОИСК БИБЛИОТЕК ВРУЧНУЮ (Fix for CLion/WSL) ---

# LibSodium
find_library(SODIUM_LIB sodium HINTS /usr/lib /usr/local/lib /usr/lib/x86_64-linux-gnu)
find_path(SODIUM_INC sodium.h HINTS /usr/include /usr/local/include)

# LibOQS (Post-Quantum)
find_library(OQS_LIB oqs HINTS /usr/lib /usr/local/lib)
find_path(OQS_INC oqs/oqs.h HINTS /usr/include /usr/local/include)

if (NOT SODIUM_LIB OR NOT OQS_LIB)
    message(FATAL_ERROR "Libraries not found! Run 'sudo apt install libsodium-dev' and check liboqs install.")
endif()

include_directories(${SODIUM_INC} ${OQS_INC} "src")

# Собираем файлы явно, чтобы CMake не терял их
add_executable(voidgate
        src/main.cpp
        src/Core.hpp
        src/CryptoEngine.hpp
        src/Protocol.hpp
)

target_link_libraries(voidgate ${SODIUM_LIB} ${OQS_LIB} pthread)

