#ifndef AES_H
#define AES_H

#include <stdint.h>

#define AES_BLOCK_SIZE 16  // AES 블록 크기 (128bit)

// AES 컨텍스트 구조체
// 다양한 키 크기(AES-128, 192, 256)를 지원하기 위한 구조체 정의
// Nk : 키 워드 수 (AES-128: 4, AES-192: 6, AES-256: 8)
// Nr : 라운드 수 (AES-128: 10, AES-192: 12, AES-256: 14)
// roundKeySize : 전체 라운드 키 바이트 수
// roundKeys : 확장된 라운드 키 저장 배열 (최대 240byte)
// Rcon : 동적 라운드 상수 배열 (최대 15개)
typedef struct {
    int Nk;
    int Nr;
    int roundKeySize;
    uint8_t roundKeys[240];
    uint8_t Rcon[15];  // Rcon[1]~[14] 사용 가능
} AES_ctx;

// AES 컨텍스트 초기화 함수
// 주어진 키와 키 사이즈(128, 192, 256 비트)에 따라 Nk, Nr 설정 및 키 확장 수행
void AES_init_ctx(AES_ctx* ctx, uint8_t* key, int key_size_bits);

// AES CBC 모드 암호화 함수 (PKCS7 패딩 포함)
// - ctx: AES 컨텍스트 (라운드 키 포함)
// - input: 평문 입력
// - output: 암호문 출력 (padded)
// - length: 평문 길이
// - iv: 초기화 벡터 (CBC용)
void AES_encrypt_CBC(AES_ctx* ctx, uint8_t* input, uint8_t* output, int length, uint8_t* iv);

// AES CBC 모드 복호화 함수 (PKCS7 제거 포함)
void AES_decrypt_CBC(AES_ctx* ctx, uint8_t* input, uint8_t* output, int length, uint8_t* iv);

// Rcon 생성 함수 선언
void generate_rcon(uint8_t* rcon_array, int count);

#endif
