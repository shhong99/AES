#ifndef AES_H
#define AES_H

#include <stdint.h>

#define AES_BLOCK_SIZE 16  // AES ��� ũ�� (128bit)

// AES ���ؽ�Ʈ ����ü
// �پ��� Ű ũ��(AES-128, 192, 256)�� �����ϱ� ���� ����ü ����
// Nk : Ű ���� �� (AES-128: 4, AES-192: 6, AES-256: 8)
// Nr : ���� �� (AES-128: 10, AES-192: 12, AES-256: 14)
// roundKeySize : ��ü ���� Ű ����Ʈ ��
// roundKeys : Ȯ��� ���� Ű ���� �迭 (�ִ� 240byte)
// Rcon : ���� ���� ��� �迭 (�ִ� 15��)
typedef struct {
    int Nk;
    int Nr;
    int roundKeySize;
    uint8_t roundKeys[240];
    uint8_t Rcon[15];  // Rcon[1]~[14] ��� ����
} AES_ctx;

// AES ���ؽ�Ʈ �ʱ�ȭ �Լ�
// �־��� Ű�� Ű ������(128, 192, 256 ��Ʈ)�� ���� Nk, Nr ���� �� Ű Ȯ�� ����
void AES_init_ctx(AES_ctx* ctx, uint8_t* key, int key_size_bits);

// AES CBC ��� ��ȣȭ �Լ� (PKCS7 �е� ����)
// - ctx: AES ���ؽ�Ʈ (���� Ű ����)
// - input: �� �Է�
// - output: ��ȣ�� ��� (padded)
// - length: �� ����
// - iv: �ʱ�ȭ ���� (CBC��)
void AES_encrypt_CBC(AES_ctx* ctx, uint8_t* input, uint8_t* output, int length, uint8_t* iv);

// AES CBC ��� ��ȣȭ �Լ� (PKCS7 ���� ����)
void AES_decrypt_CBC(AES_ctx* ctx, uint8_t* input, uint8_t* output, int length, uint8_t* iv);

// Rcon ���� �Լ� ����
void generate_rcon(uint8_t* rcon_array, int count);

#endif
