#include <stdio.h>
#include <string.h>
#include <ctype.h>

static void base36_encode(const unsigned char *input, size_t input_len, char *output, size_t output_size) {
    if (input_len == 0 || output_size == 0) {
        if (output_size > 0) {
            output[0] = '0';
            output[1] = '\0';
        }
        return;
    }
    
    unsigned char num[512] = {0};
    size_t num_len = input_len;
    
    if (num_len > sizeof(num)) {
        num_len = sizeof(num);
    }
    
    memcpy(num, input, num_len);
    
    char result[1024];
    int result_len = 0;
    
    while (num_len > 0) {
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
        
        unsigned int remainder = 0;
        for (size_t i = 0; i < num_len; i++) {
            unsigned int current = remainder * 256 + num[i];
            num[i] = current / 36;
            remainder = current % 36;
        }
        
        if (result_len < (int)sizeof(result) - 1) {
            if (remainder < 10) {
                result[result_len++] = '0' + remainder;
            } else {
                result[result_len++] = 'a' + (remainder - 10);
            }
        }
        
        size_t first_nonzero = 0;
        while (first_nonzero < num_len && num[first_nonzero] == 0) {
            first_nonzero++;
        }
        
        if (first_nonzero > 0 && first_nonzero < num_len) {
            memmove(num, num + first_nonzero, num_len - first_nonzero);
            num_len -= first_nonzero;
        } else if (first_nonzero >= num_len) {
            num_len = 0;
        }
    }
    
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

int main() {
    char output[512];
    
    // Test CHUNK message
    const char *msg = "CHUNK|0|172.30.198.157|stg_1762371869494360576_8085";
    base36_encode((const unsigned char *)msg, strlen(msg), output, sizeof(output));
    printf("Input: %s\n", msg);
    printf("Output: %s\n", output);
    printf("Output len: %zu\n", strlen(output));
    
    return 0;
}
