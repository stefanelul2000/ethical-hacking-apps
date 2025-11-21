// Network and system headers
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <dlfcn.h>
#include <openssl/evp.h>

// Standard C++ headers
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <string>
#include <vector>
#include <random>
#include <functional>
#include <iostream>
#include <memory>

// Helper macros for better readability
#define FORCE_INLINE inline __attribute__((always_inline))
#define ZERO_MEMORY(x) std::memset((x), 0, sizeof(x))
#define COPY_MEMORY(dest, src, n) std::memcpy((dest), (src), (n))
#define SOCKET_SEND(fd, buf, n, flags) send((fd), (buf), (n), (flags))
#define SOCKET_RECV(fd, buf, n) recv((fd), (buf), (n), 0)

// Cryptographic helper functions
// Rotate left by r bits
static inline uint8_t rotate_left_8(uint8_t x, unsigned r)
{
    return (x << (r & 7)) | (x >> ((8 - r) & 7));
}

// Rotate right by r bits
static inline uint8_t rotate_right_8(uint8_t x, unsigned r)
{
    return (x >> (r & 7)) | (x << ((8 - r) & 7));
}

// S-box for cryptographic transformations
static const std::array<uint8_t, 256> SUBSTITUTION_BOX = []
{
    std::array<uint8_t, 256> table{};
    uint8_t value = 0x63;

    // Initialize with pseudo-random values
    for (size_t i = 0; i < 256; i++)
    {
        table[i] = value;
        value = value * 29u + 17u;
    }

    // Apply rotation transformation
    for (size_t i = 0; i < 256; i++)
    {
        table[i] = rotate_left_8((uint8_t)(table[i] ^ 0xA5u), i % 7);
    }

    // Set specific values
    table[0] = 0xB7;
    table[0x63] = 0x63;
    table[0xA5] = 0x5A;
    table[0xFF] = 0x11;

    return table;
}();

// Galois field multiplication for AES-like operations
static inline uint8_t galois_multiply(uint8_t a, uint8_t b)
{
    uint8_t product = 0;
    for (int i = 0; i < 8; i++)
    {
        if (b & 1)
            product ^= a;
        uint8_t high_bit = (a & 0x80);
        a <<= 1;
        if (high_bit)
            a ^= 0x1B; // AES irreducible polynomial
        b >>= 1;
    }
    return product;
}

// Feistel network block cipher operation
static inline void feistel_block_cipher(uint8_t &left, uint8_t &right, uint8_t key1, uint8_t key2)
{
    // First round
    uint8_t function_output = SUBSTITUTION_BOX[(uint8_t)(left ^ key1)];
    right ^= rotate_left_8((uint8_t)(galois_multiply(function_output, 0xB1) ^ key1), (key1 & 7));
    std::swap(left, right);

    // Second round
    function_output = SUBSTITUTION_BOX[(uint8_t)(left ^ key2)];
    right ^= rotate_right_8((uint8_t)(galois_multiply(function_output, 0x5D) ^ key2), (key2 & 7));
    std::swap(left, right);
}

// Custom key verification/encryption function
std::vector<uint8_t> verify_and_transform_key(const uint8_t *input, size_t length)
{
    std::vector<uint8_t> data(input, input + length);

    // Step 1: Linear congruential generator XOR transformation
    uint32_t lcg_state = 0xC0FFEE01u;
    for (size_t i = 0; i < length; ++i)
    {
        lcg_state = lcg_state * 1664525u + 1013904223u;
        uint8_t mask = (uint8_t)((lcg_state >> ((i * 3) & 31)) ^ (lcg_state >> 24));
        data[i] ^= (uint8_t)(mask + (uint8_t)i);
    }

    // Step 2: Rotation with carry propagation
    uint8_t carry = 0x5A;
    for (size_t i = 0; i < length; ++i)
    {
        uint8_t x = data[i] ^ carry;
        x = (i & 1) ? rotate_left_8(x, (int)((i ^ carry) & 7)) : rotate_right_8(x, (int)((i + carry) & 7));
        carry = (uint8_t)(carry + x * 0x3D);
        data[i] = x ^ (uint8_t)((i * 0x77u) ^ (carry >> 1));
    }

    // Step 3: Position-based swapping
    for (size_t i = 0; i + 3 < length; i += 5)
    {
        std::swap(data[i], data[i + 3]);
        if (i + 5 < length)
            std::swap(data[i + 1], data[i + 5 < length ? i + 2 : i + 1]);
    }

    // Step 4: Feistel network application
    for (size_t i = 0; i + 1 < length; i += 2)
    {
        uint8_t k1 = (uint8_t)(0xA3 ^ ((i * 0x1F) + data[i]));
        uint8_t k2 = (uint8_t)(0x7D ^ ((i * 0x2B) + data[i + 1]));
        feistel_block_cipher(data[i], data[i + 1], k1, k2);
    }

    // Step 5: MixColumns-like transformation (AES-inspired)
    for (size_t i = 0; i + 3 < length; i += 4)
    {
        uint8_t a = data[i], b = data[i + 1], c = data[i + 2], d = data[i + 3];
        uint8_t a2 = (uint8_t)(galois_multiply(a, 2) ^ galois_multiply(b, 3) ^ c ^ d);
        uint8_t b2 = (uint8_t)(a ^ galois_multiply(b, 2) ^ galois_multiply(c, 3) ^ d);
        uint8_t c2 = (uint8_t)(a ^ b ^ galois_multiply(c, 2) ^ galois_multiply(d, 3));
        uint8_t d2 = (uint8_t)(galois_multiply(a, 3) ^ b ^ c ^ galois_multiply(d, 2));
        data[i] = a2;
        data[i + 1] = b2;
        data[i + 2] = c2;
        data[i + 3] = d2;
    }

    // Step 6: Final substitution layer
    for (size_t i = 0; i < length; ++i)
    {
        data[i] = (uint8_t)(SUBSTITUTION_BOX[data[i]] ^ (uint8_t)((0x55 + i * 13) & 0xFF));
    }

    return data;
}

/*
    in C++ un namespace este folosit ca sa grupezi
    functii si variabile ca sa nu existe conflicte
    astfel poti sa ai mai multe functii cu acelasi nume
    atata timp cat sunt in namespace-uri diferite

*/

namespace ServerNamespace
{

    // Random number generator
    static std::mt19937_64 random_generator(0);

    // Random number generators
    FORCE_INLINE uint8_t random_byte()
    {
        return static_cast<uint8_t>(random_generator() & 0xFF);
    }

    FORCE_INLINE uint32_t random_uint32()
    {
        return static_cast<uint32_t>(random_generator());
    }

    // Simple obfuscation mixer
    FORCE_INLINE uint32_t mix_uint32(uint32_t x)
    {
        x ^= 0xA5A5A5A5u;
        x = (x << 7) | (x >> 25);
        x ^= random_uint32();
        return x;
    }

    // XOR cipher with random stream
    void xor_cipher(uint8_t *buffer, size_t length, uint8_t key)
    {
        for (size_t i = 0; i < length; i++)
        {
            buffer[i] ^= (uint8_t)(key ^ random_byte() ^ (i & 0xFF));
        }
    }

    // Base64 decoder
    size_t base64_decode(const char *input, uint8_t *output, size_t output_size)
    {
       
        EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
        int outlen = 0, tmplen = 0;

        EVP_DecodeInit(ctx);

        int ret = EVP_DecodeUpdate(ctx, output, &outlen, (unsigned char*)input, strlen(input));
        if (ret < 0) { EVP_ENCODE_CTX_free(ctx); return 0; }

        ret = EVP_DecodeFinal(ctx, output + outlen, &tmplen);
        EVP_ENCODE_CTX_free(ctx);

        if (ret < 0)
            return 0;

        return outlen + tmplen;
    }

    // Decode base64 string
    std::string decode_transform(const char *base64_blob, uint8_t salt)
    {
        uint8_t temp[128];
        ZERO_MEMORY(temp);
        size_t decoded_length = base64_decode(base64_blob, temp, sizeof(temp));
        std::string result((char *)temp, decoded_length);

        // Remove trailing whitespace/control characters
        while (!result.empty() && (unsigned char)result.back() < 0x20)
        {
            result.pop_back();
        }
        return result;
    }

    // Command keywords (base64 encoded)
    static const char COMMAND_STACK[] = "U1RBS0s="; // "STAKK"
    static const char COMMAND_HEAP[] = "SEVBUA==";  // "HEAP"
    static const char COMMAND_RET[] = "UkVU";       // "RET"
    static const char COMMAND_QUIT[] = "UVVJVA==";  // "QUIT"
    static const char COMMAND_ASM[] = "QVNN";       // "ASM"

    // Response messages (base64 encoded)
    static const char RESPONSE_READY_STACK[] = "UkVBRFk6U1RBQ0sK"; // "READY:STACK\n"
    static const char RESPONSE_READY_HEAP[] = "UkVBRFk6SEVBUEoK";  // "READY:HEAPJ\n"
    static const char RESPONSE_READY_RET[] = "UkVBRFk6UkVUCg==";   // "READY:RET\n"
    static const char RESPONSE_BYE[] = "QllFCg==";                 // "BYE\n"
    static const char RESPONSE_UNKNOWN[] = "VU5LTk9XTgo=";         // "UNKNOWN\n"
    static const char RESPONSE_READY_ASM[] = "UkVBRFk6QVNNCg==";   // "READY:ASM\n"

    // Function pointer type for vulnerability handlers
    using vulnerability_handler = void (*)(int);

    // Forward declarations
    void handle_stack_overflow(int socket_fd);
    void handle_heap_overflow(int socket_fd);
    void handle_return_oriented_programming(int socket_fd);
    void handle_assembly_vuln(int socket_fd);
    void handle_client_connection(int socket_fd);

    // Read a line from socket
    int read_line_from_socket(int fd, char *output, size_t max_size)
    {
        size_t i = 0;
        while (i < max_size - 1)
        {
            ssize_t received = SOCKET_RECV(fd, output + i, 1);
            if (received <= 0)
                break;
            if (output[i] == '\n')
            {
                ++i;
                break;
            }
            ++i;
        }
        output[i] = 0;
        return (int)i;
    }

    // VULNERABILITY 1: Stack-based buffer overflow
    void handle_stack_overflow(int socket_fd)
    {
        char small_buffer[48]; // Small buffer on stack
        char message[512];
        ZERO_MEMORY(message);

        int bytes_received = SOCKET_RECV(socket_fd, message, sizeof(message) - 1);
        if (bytes_received <= 0)
            return;
        message[bytes_received] = 0;

        // DANGEROUS: strcpy without bounds checking!
        /*
            FIXED 
        */
        strncpy(small_buffer, message, sizeof(small_buffer) - 1);
        small_buffer[sizeof(small_buffer) - 1] = 0;          // Buffer overflow if message > 48 bytes

        SOCKET_SEND(socket_fd, small_buffer, strlen(small_buffer), 0);
    }

    // VULNERABILITY 2: Heap-based buffer overflow
    void handle_heap_overflow(int socket_fd)
    {
        struct HeapBox
        {
            char data[24];
            uint32_t tag;
        };

        HeapBox *heap_ptr = new HeapBox;
        heap_ptr->tag = 0x41424344u ^ mix_uint32(0x55);

        char message[512];
        ZERO_MEMORY(message);
        int bytes_received = SOCKET_RECV(socket_fd, message, sizeof(message) - 1);
        if (bytes_received <= 0)
        {
            delete heap_ptr;
            return;
        }
        message[bytes_received] = 0;

        // DANGEROUS: memcpy without bounds checking!

        /*
                FIX VULN 2

        */
        size_t safe_len = strnlen(message, sizeof(heap_ptr->data) - 1);
        memcpy(heap_ptr->data, message, safe_len);
        heap_ptr->data[safe_len] = 0;
        
        // Can overflow into 'tag'

        SOCKET_SEND(socket_fd, heap_ptr->data, strlen(heap_ptr->data), 0);
        delete heap_ptr;
    }

    // VULNERABILITY 3: Return address overwrite
    void handle_return_oriented_programming(int socket_fd)
    {
        char stack_buffer[32];
        char message[256];
        ZERO_MEMORY(message);

        int bytes_received = SOCKET_RECV(socket_fd, message, sizeof(message) - 1);
        if (bytes_received <= 0)
            return;
        message[bytes_received] = 0;

        // DANGEROUS: strcpy without bounds checking on stack!
        snprintf(stack_buffer, sizeof(stack_buffer), "%s", message); // Can overwrite return address

        SOCKET_SEND(socket_fd, "OK\n", 3, 0);
    }

    // VULNERABILITY 4: Assembly buffer overflow with rep movsb
void handle_assembly_vuln(int socket_fd)
{
    uint8_t source[512];
    ZERO_MEMORY(source);

    int bytes_received = SOCKET_RECV(socket_fd, source, sizeof(source) - 1);
    if (bytes_received <= 0)
        return;

    source[bytes_received] = 0;

    uint8_t destination[40];
    ZERO_MEMORY(destination);

    // FIX: no raw rep movsb
    size_t safe_len = strnlen((char*)source, sizeof(destination) - 1);
    memcpy(destination, source, safe_len);
    destination[safe_len] = 0;

    SOCKET_SEND(socket_fd, destination, safe_len, 0);
}

    // Array of vulnerability handlers
    vulnerability_handler vulnerability_handlers[] = {
        handle_stack_overflow,
        handle_heap_overflow,
        handle_return_oriented_programming,
        handle_assembly_vuln};

    // Main request handler - dispatches to appropriate vulnerability
    void handle_client_connection(int socket_fd)
    {
        // Decode command keywords
        std::string keyword_stack = decode_transform(COMMAND_STACK, 0x5A);
        std::string keyword_heap = decode_transform(COMMAND_HEAP, 0x5A);
        std::string keyword_ret = decode_transform(COMMAND_RET, 0x5A);
        std::string keyword_quit = decode_transform(COMMAND_QUIT, 0x5A);
        std::string keyword_asm = decode_transform(COMMAND_ASM, 0x5A);

        // Decode response messages
        std::string response_stack = decode_transform(RESPONSE_READY_STACK, 0xA5);
        std::string response_heap = decode_transform(RESPONSE_READY_HEAP, 0xA5);
        std::string response_ret = decode_transform(RESPONSE_READY_RET, 0xA5);
        std::string response_bye = decode_transform(RESPONSE_BYE, 0xA5);
        std::string response_unknown = decode_transform(RESPONSE_UNKNOWN, 0xA5);
        std::string response_asm = decode_transform(RESPONSE_READY_ASM, 0xA5);

        // Read command from client
        char client_command[128];
        ZERO_MEMORY(client_command);
        int bytes_read = read_line_from_socket(socket_fd, client_command, sizeof(client_command));
        if (bytes_read <= 0)
            return;

        // Trim trailing newlines/carriage returns
        while (bytes_read > 0 && (client_command[bytes_read - 1] == '\n' || client_command[bytes_read - 1] == '\r'))
        {
            client_command[--bytes_read] = 0;
        }

        // String comparison with obfuscation
        bool string_equals_safe(const std::string& a, const char* b)
        {
            return a == std::string(b);
        }

        // Dispatch to appropriate vulnerability handler
        if (string_equals(keyword_stack, client_command))
        {
            SOCKET_SEND(socket_fd, response_stack.data(), response_stack.size(), 0);
            vulnerability_handlers[0](socket_fd);
        }
        else if (string_equals(keyword_heap, client_command))
        {
            SOCKET_SEND(socket_fd, response_heap.data(), response_heap.size(), 0);
            vulnerability_handlers[1](socket_fd);
        }
        else if (string_equals(keyword_ret, client_command))
        {
            SOCKET_SEND(socket_fd, response_ret.data(), response_ret.size(), 0);
            vulnerability_handlers[2](socket_fd);
        }
        else if (string_equals(keyword_asm, client_command))
        {
            SOCKET_SEND(socket_fd, response_asm.data(), response_asm.size(), 0);
            vulnerability_handlers[3](socket_fd);
        }
        else if (string_equals(keyword_quit, client_command))
        {
            SOCKET_SEND(socket_fd, response_bye.data(), response_bye.size(), 0);
        }
        else
        {
            SOCKET_SEND(socket_fd, response_unknown.data(), response_unknown.size(), 0);
        }
    }

    // Global flag for server shutdown
    // aici ai operatii atomice adica nu pot sa fie intrerupte la jumatate
    //se folosesc pentru variabile modificate intre ele
    volatile sig_atomic_t server_running = 1;

    // Signal handler for graceful shutdown
    void signal_handler(int signal)
    {
        server_running = 0;
    }

    // Display API key transformation
    void display_api_key_transform(auto api_key)
    {
        auto output = verify_and_transform_key(api_key, std::strlen((const char *)api_key));
        for (size_t i = 0; i < output.size(); ++i)
        {
            std::printf("%02X%s", output[i], (i + 1) % 16 ? " " : "\n");
        }
        std::puts("");
    }

    // Main server loop
    int server_main_loop()
    {

        // aici este un char cu pi ca cu
        unsigned char api_key_data[] = {
            0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20,
            0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20,
            0x70, 0x69, 0x6B, 0x61, 0x20, 0x70, 0x69, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69,
            0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20,
            0x70, 0x69, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70,
            0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70,
            0x69, 0x63, 0x68, 0x75, 0x20, 0x70, 0x69, 0x63, 0x68, 0x75, 0x20, 0x70, 0x69, 0x63, 0x68,
            0x75, 0x20, 0x70, 0x69, 0x63, 0x68, 0x75, 0x20, 0x6B, 0x61, 0x20, 0x63, 0x68, 0x75, 0x20,
            0x70, 0x69, 0x70, 0x69, 0x20, 0x70, 0x69, 0x70, 0x69, 0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61,
            0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x70, 0x69, 0x6B, 0x61, 0x63,
            0x68, 0x75, 0x20, 0x70, 0x69, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70,
            0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70,
            0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x6B, 0x61, 0x63, 0x68, 0x75, 0x20, 0x6B, 0x61,
            0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61,
            0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61,
            0x20, 0x70, 0x69, 0x6B, 0x61, 0x63, 0x68, 0x75, 0x20, 0x70, 0x69, 0x63, 0x68, 0x75, 0x20,
            0x70, 0x69, 0x63, 0x68, 0x75, 0x20, 0x70, 0x69, 0x63, 0x68, 0x75, 0x20, 0x70, 0x69, 0x20,
            0x70, 0x69, 0x20, 0x70, 0x69, 0x6B, 0x61, 0x63, 0x68, 0x75, 0x20, 0x70, 0x69, 0x70, 0x69,
            0x20, 0x70, 0x69, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20,
            0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20,
            0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x6B, 0x61, 0x63, 0x68, 0x75, 0x20, 0x6B,
            0x61, 0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x6B,
            0x61, 0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x6B,
            0x61, 0x20, 0x70, 0x69, 0x6B, 0x61, 0x63, 0x68, 0x75, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69,
            0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x6B, 0x61, 0x63, 0x68, 0x75, 0x20,
            0x70, 0x69, 0x63, 0x68, 0x75, 0x20, 0x70, 0x69, 0x63, 0x68, 0x75, 0x20, 0x70, 0x69, 0x6B,
            0x61, 0x63, 0x68, 0x75, 0x20, 0x70, 0x69, 0x70, 0x69, 0x20, 0x70, 0x69, 0x70, 0x69, 0x20,
            0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20,
            0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20,
            0x6B, 0x61, 0x20, 0x70, 0x69, 0x6B, 0x61, 0x63, 0x68, 0x75, 0x20, 0x70, 0x69, 0x20, 0x70,
            0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70,
            0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x6B, 0x61, 0x63, 0x68, 0x75, 0x20, 0x70, 0x69,
            0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x6B, 0x61, 0x63,
            0x68, 0x75, 0x20, 0x70, 0x69, 0x63, 0x68, 0x75, 0x20, 0x70, 0x69, 0x63, 0x68, 0x75, 0x20,
            0x70, 0x69, 0x6B, 0x61, 0x63, 0x68, 0x75, 0x20, 0x70, 0x69, 0x70, 0x69, 0x20, 0x70, 0x69,
            0x70, 0x69, 0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20,
            0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20,
            0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x70, 0x69, 0x6B, 0x61, 0x63, 0x68, 0x75, 0x20, 0x70,
            0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70,
            0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x6B, 0x61, 0x63, 0x68, 0x75,
            0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x20, 0x70, 0x69,
            0x20, 0x70, 0x69, 0x20, 0x70, 0x69, 0x6B, 0x61, 0x63, 0x68, 0x75, 0x20, 0x70, 0x69, 0x63,
            0x68, 0x75, 0x20, 0x70, 0x69, 0x63, 0x68, 0x75, 0x20, 0x70, 0x69, 0x6B, 0x61, 0x63, 0x68,
            0x75, 0x20, 0x70, 0x69, 0x70, 0x69, 0x20, 0x70, 0x69, 0x70, 0x69, 0x20, 0x6B, 0x61, 0x20,
            0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20,
            0x6B, 0x61, 0x20, 0x6B, 0x61, 0x20, 0x70, 0x69, 0x6B, 0x61, 0x63, 0x68, 0x75, 0x20, 0x70,
            0x69, 0x63, 0x68, 0x75, 0x20, 0x70, 0x69, 0x63, 0x68, 0x75, 0x20, 0x70, 0x69, 0x6B, 0x61,
            0x63, 0x68, 0x75, 0x00};


       
        const int SERVER_PORT = 4444;

        // Create socket TCP/IP
        // AF_INET - spune ca va folosi IPv4
        //SOCK_STREAM - ca este TCP - flux de date ordonat
        // 0 pentru default protocol pus din conventie
        int server_socket = socket(AF_INET, SOCK_STREAM, 0);
        // daca returneaza ceva mai mic de zero cum ar fii -1 
        // functia a esuat
        if (server_socket < 0)
        {
            perror("socket");
            return 1;
        }

        // Set socket options
        int socket_option = 1;
        // functia este folosita pentru a configura socket-ul
        /*
            server_socket = e socketul definit mai sus pe care aplici optiunea
            SOL_SOCKET - nivelul de optiuni - socket general aici
            SO_REUSEADDR - permite refolosirea adresei portului imediat dupa ce serverul se opreste
            fara sa astepti timeout daca nu portul ramane blocat si e nasol

            socket_option = 1 - e activat

            sizeof(socket_option) - dimensiunea variabilei sa stie cat sa citeasca
        */

        setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &socket_option, sizeof(socket_option));

        // Configure server address

        // aici se creeaza o structura de tipul sockaddr_in 
        sockaddr_in server_addr;

        // Initializeaza structura cu 0 - asta ca sa nu ramana valori random in campuri nefolosite

        ZERO_MEMORY(&server_addr);

        //seteaza familia de adrese la IPV4
        // adica socket-ul va folosi adrese de tipul 192.168.x.x
        server_addr.sin_family = AF_INET;
        // aici se seteaza portul la care se va asculta 
        //htons converteste din little endian la formatul masinii
        server_addr.sin_port = htons(SERVER_PORT);
        // aici spune ca serverul va asculta pe toate interfetele posibile
        server_addr.sin_addr.s_addr = INADDR_ANY;

        // Bind socket - ce face este ca leaga socketul server_socket de o adresa
        // si de un port specific 
        if (bind(server_socket, (sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        {
            perror("bind");
            close(server_socket);
            return 1;
        }

        // Listen for connections
        // listen - pune serverul in modul server adica pregateste sa asculte
        // conexiuni de la clienti

        // 5 numarul maxim de conexiuni ce poate sa stea in coada

        if (listen(server_socket, 5) < 0)
        {
            perror("listen");
            close(server_socket);
            return 1;
        }

        std::fprintf(stdout, "[*] Server listening on port %d\n", SERVER_PORT);

        // Main accept loop
        while (server_running)
        {
              
            //sockaddr_in - retine adresa unui client 
            sockaddr_in client_addr;

            //defineste o variabila client_addr_len de tip socklen_t
            // initiaza cu dimensiunea structurii client_addr
            socklen_t client_addr_len = sizeof(client_addr);


            // accept - asteapta un client sa se conecteze la server_socket
            // cand se conecteaza creeaza un nou socket dedicat acestui client
            // completeaza client_addr cu info despre client IP, port
            int client_socket = accept(server_socket, (sockaddr *)&client_addr, &client_addr_len);
            if (client_socket < 0)
            {
                if (errno == EINTR)
                    continue;
                perror("accept");
                break;
            }

            // Fork child process to handle client (prevents server crash on segfault)
            pid_t pid = fork();
            if (pid == 0)
            {
                // Child process
                close(server_socket); // Child doesn't need the listening socket
                handle_client_connection(client_socket);
                close(client_socket);
                _exit(0); // Exit child process
            }
            else if (pid > 0)
            {
                // Parent process
                close(client_socket); // Parent doesn't need the client socket
            }
            else
            {
                perror("fork");
            }
        }

        // Display transformed API key on shutdown
        display_api_key_transform(api_key_data);
        close(server_socket);
        return 0;
    }

} // namespace ServerNamespace

int main()
{

    // daca userul apasa CTRL+ C se va executa aceasta functie
    // cand apesi CTRL+C se va rula signal handler
    struct sigaction sa;
    sa.sa_handler = ServerNamespace::signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGINT, &sa, NULL);
    return ServerNamespace::server_main_loop();
}
