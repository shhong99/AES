#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "aes.h"

int main() {
    // 입력 평문 정확히 20바이트로 설정 (널 문자 없음)
    uint8_t plaintext[21] = {
        '2','0','1','8','2','4','6','1','3',
        'h','o','n','g','s','e','o','k','h','y','u','n'
    };
    int len = 21;  // 고정 길이 지정
    int pad = 16 - (len % 16);
    int total_len = len + pad;

    //  키 및 IV 설정
    int key_size_bits = 256;
    int key_size_bytes = key_size_bits / 8;

    // 최대 256비트까지 지원하는 마스터 키
    uint8_t master_key[32] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        0x76, 0x2e, 0xd5, 0x68, 0x11, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98
    };

    // 실제 사용할 키 배열 (요청된 크기만큼 복사)
    uint8_t key[32];
    memcpy(key, master_key, key_size_bytes);

    // 초기화 벡터 (CBC 모드에서 첫 블록에 XOR용)
    uint8_t iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    // 암호문/복호문 저장 공간 동적 할당
    uint8_t* ciphertext = malloc(total_len);
    uint8_t* decrypted = malloc(total_len);

    // AES 컨텍스트 초기화 및 키 확장 수행
    AES_ctx ctx;
    AES_init_ctx(&ctx, key, key_size_bits);

    // 시간 측정 시작
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    // CBC 암호화 수행
    AES_encrypt_CBC(&ctx, plaintext, ciphertext, len, iv);

    // CBC 복호화 수행
    AES_decrypt_CBC(&ctx, ciphertext, decrypted, total_len, iv);

    // 시간 측정 끝
    clock_gettime(CLOCK_MONOTONIC, &end);

    // 경과 시간 계산 및 출력
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("암호화 + 복호화 걸린 시간: %.9f 초\n", elapsed);

    // 암호문 출력 (hex)
    printf("Ciphertext (hex): ");
    for (int i = 0; i < total_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // 암호문 파일로 저장 (ciphertext.bin)
    FILE* f_enc = fopen("ciphertext.bin", "wb");
    if (f_enc) {
        fwrite(ciphertext, 1, total_len, f_enc);
        fclose(f_enc);
        printf("암호문을 ciphertext.bin 파일에 저장했습니다.\n");
    } else {
        printf("암호문 파일 저장 실패\n");
    }

    // 암호문 파일에서 읽기
    FILE* f_dec = fopen("ciphertext.bin", "rb");
    if (f_dec) {
        fread(ciphertext, 1, total_len, f_dec);
        fclose(f_dec);
        printf("ciphertext.bin 파일에서 암호문을 읽었습니다.\n");
    } else {
        printf("암호문 파일 열기 실패\n");
    }

    // 복호화된 텍스트 출력
    printf("Decrypted Text : ");
    for (int i = 0; i < len; i++) {
        printf("%c", decrypted[i]);
    }
    printf("\n");

    // 복호화된 텍스트를 파일로 저장
    FILE* f_out = fopen("decrypted.txt", "w");
    if (f_out) {
        fwrite(decrypted, 1, len, f_out);
        fclose(f_out);
        printf("복호화된 텍스트를 decrypted.txt 파일에 저장했습니다.\n");
    } else {
        printf("복호문 파일 저장 실패\n");
    }

    // 메모리 해제
    free(ciphertext);
    free(decrypted);
    return 0;
}
