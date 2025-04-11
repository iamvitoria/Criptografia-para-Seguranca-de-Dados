#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

// Base64 decoding table
const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int base64_char_value(char c) {
    const char* ptr = strchr(base64_table, c);
    if (ptr) return ptr - base64_table;
    return -1;
}

// Decodifica uma string base64
unsigned char* base64_decode(const char* input, size_t* out_len) {
    size_t len = strlen(input);
    size_t padding = 0;
    if (len >= 1 && input[len - 1] == '=') padding++;
    if (len >= 2 && input[len - 2] == '=') padding++;

    *out_len = (len * 3) / 4 - padding;
    unsigned char* decoded = malloc(*out_len);
    if (!decoded) return NULL;

    for (size_t i = 0, j = 0; i < len;) {
        int sextet_a = base64_char_value(input[i++]);
        int sextet_b = base64_char_value(input[i++]);
        int sextet_c = base64_char_value(input[i++]);
        int sextet_d = base64_char_value(input[i++]);

        uint32_t triple = (sextet_a << 18) + (sextet_b << 12) +
                          ((sextet_c & 63) << 6) + (sextet_d & 63);

        if (j < *out_len) decoded[j++] = (triple >> 16) & 0xFF;
        if (j < *out_len) decoded[j++] = (triple >> 8) & 0xFF;
        if (j < *out_len) decoded[j++] = triple & 0xFF;
    }

    return decoded;
}

// Calcula a distância de Hamming entre dois buffers
int hamming_distance(const unsigned char* a, const unsigned char* b, size_t len) {
    int dist = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char val = a[i] ^ b[i];
        while (val) {
            dist += val & 1;
            val >>= 1;
        }
    }
    return dist;
}

// Adivinha o tamanho da chave baseado na distância de Hamming
int estimate_key_size(const unsigned char* data, size_t len) {
    int best_key_size = 2;
    float best_distance = 1e9;

    for (int key_size = 2; key_size <= 40; key_size++) {
        if (key_size * 4 > len) break;

        int d1 = hamming_distance(data, data + key_size, key_size);
        int d2 = hamming_distance(data + key_size, data + 2 * key_size, key_size);
        int d3 = hamming_distance(data + 2 * key_size, data + 3 * key_size, key_size);
        int d4 = hamming_distance(data + 3 * key_size, data + 4 * key_size, key_size);

        float avg = (d1 + d2 + d3 + d4) / 4.0f / key_size;

        if (avg < best_distance) {
            best_distance = avg;
            best_key_size = key_size;
        }
    }

    return best_key_size;
}

// Análise de frequência para identificar a melhor letra da chave
unsigned char break_single_byte_xor(const unsigned char* block, size_t len) {
    int max_score = -1;
    unsigned char best_key = 0;

    for (int k = 0; k < 256; k++) {
        int score = 0;
        for (size_t i = 0; i < len; i++) {
            unsigned char c = block[i] ^ k;
            if (isalpha(c) || isspace(c)) score++;
        }
        if (score > max_score) {
            max_score = score;
            best_key = k;
        }
    }
    return best_key;
}

// Quebra a cifra com XOR de chave repetida
unsigned char* break_repeating_key_xor(const unsigned char* data, size_t len, int key_size, unsigned char* key_out) {
    for (int i = 0; i < key_size; i++) {
        size_t block_len = (len - i + key_size - 1) / key_size;
        unsigned char* block = malloc(block_len);
        for (size_t j = 0; j < block_len; j++) {
            if (i + j * key_size < len)
                block[j] = data[i + j * key_size];
        }
        key_out[i] = break_single_byte_xor(block, block_len);
        free(block);
    }

    unsigned char* decrypted = malloc(len + 1);
    for (size_t i = 0; i < len; i++) {
        decrypted[i] = data[i] ^ key_out[i % key_size];
    }
    decrypted[len] = '\0';
    return decrypted;
}

int main() {
    FILE* f = fopen("cifra.base64", "r");
    if (!f) {
        perror("Erro ao abrir o arquivo");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char* base64_data = malloc(size + 1);
    fread(base64_data, 1, size, f);
    base64_data[size] = '\0';
    fclose(f);

    size_t decoded_len;
    unsigned char* decoded = base64_decode(base64_data, &decoded_len);
    if (!decoded) {
        printf("Falha na decodificação base64\n");
        return 1;
    }

    int key_size = estimate_key_size(decoded, decoded_len);
    printf("Tamanho estimado da chave: %d\n", key_size);

    unsigned char* key = malloc(key_size);
    unsigned char* plaintext = break_repeating_key_xor(decoded, decoded_len, key_size, key);

    printf("Chave descoberta (hex): ");
    for (int i = 0; i < key_size; i++) {
        printf("%02x ", key[i]);
    }
    printf("\n\nTexto decifrado:\n%s\n", plaintext);

    free(base64_data);
    free(decoded);
    free(key);
    free(plaintext);
    return 0;
}
