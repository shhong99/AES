#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "aes.h"

int main() {
    // �Է� �� ��Ȯ�� 20����Ʈ�� ���� (�� ���� ����)
    uint8_t plaintext[21] = {
        '2','0','1','8','2','4','6','1','3',
        'h','o','n','g','s','e','o','k','h','y','u','n'
    };
    int len = 21;  // ���� ���� ����
    int pad = 16 - (len % 16);
    int total_len = len + pad;

    //  Ű �� IV ����
    int key_size_bits = 256;
    int key_size_bytes = key_size_bits / 8;

    // �ִ� 256��Ʈ���� �����ϴ� ������ Ű
    uint8_t master_key[32] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        0x76, 0x2e, 0xd5, 0x68, 0x11, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98
    };

    // ���� ����� Ű �迭 (��û�� ũ�⸸ŭ ����)
    uint8_t key[32];
    memcpy(key, master_key, key_size_bytes);

    // �ʱ�ȭ ���� (CBC ��忡�� ù ��Ͽ� XOR��)
    uint8_t iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    // ��ȣ��/��ȣ�� ���� ���� ���� �Ҵ�
    uint8_t* ciphertext = malloc(total_len);
    uint8_t* decrypted = malloc(total_len);

    // AES ���ؽ�Ʈ �ʱ�ȭ �� Ű Ȯ�� ����
    AES_ctx ctx;
    AES_init_ctx(&ctx, key, key_size_bits);

    // �ð� ���� ����
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    // CBC ��ȣȭ ����
    AES_encrypt_CBC(&ctx, plaintext, ciphertext, len, iv);

    // CBC ��ȣȭ ����
    AES_decrypt_CBC(&ctx, ciphertext, decrypted, total_len, iv);

    // �ð� ���� ��
    clock_gettime(CLOCK_MONOTONIC, &end);

    // ��� �ð� ��� �� ���
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("��ȣȭ + ��ȣȭ �ɸ� �ð�: %.9f ��\n", elapsed);

    // ��ȣ�� ��� (hex)
    printf("Ciphertext (hex): ");
    for (int i = 0; i < total_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // ��ȣ�� ���Ϸ� ���� (ciphertext.bin)
    FILE* f_enc = fopen("ciphertext.bin", "wb");
    if (f_enc) {
        fwrite(ciphertext, 1, total_len, f_enc);
        fclose(f_enc);
        printf("��ȣ���� ciphertext.bin ���Ͽ� �����߽��ϴ�.\n");
    } else {
        printf("��ȣ�� ���� ���� ����\n");
    }

    // ��ȣ�� ���Ͽ��� �б�
    FILE* f_dec = fopen("ciphertext.bin", "rb");
    if (f_dec) {
        fread(ciphertext, 1, total_len, f_dec);
        fclose(f_dec);
        printf("ciphertext.bin ���Ͽ��� ��ȣ���� �о����ϴ�.\n");
    } else {
        printf("��ȣ�� ���� ���� ����\n");
    }

    // ��ȣȭ�� �ؽ�Ʈ ���
    printf("Decrypted Text : ");
    for (int i = 0; i < len; i++) {
        printf("%c", decrypted[i]);
    }
    printf("\n");

    // ��ȣȭ�� �ؽ�Ʈ�� ���Ϸ� ����
    FILE* f_out = fopen("decrypted.txt", "w");
    if (f_out) {
        fwrite(decrypted, 1, len, f_out);
        fclose(f_out);
        printf("��ȣȭ�� �ؽ�Ʈ�� decrypted.txt ���Ͽ� �����߽��ϴ�.\n");
    } else {
        printf("��ȣ�� ���� ���� ����\n");
    }

    // �޸� ����
    free(ciphertext);
    free(decrypted);
    return 0;
}
