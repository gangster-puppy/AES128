#include "../include/aes128.h"

int main() {
    int resCode(0);
    aes128::AES128 aes;
    aes128::UCHAR iv[AES_BLOCK_SIZE];
    aes128::UCHAR iv_dec[AES_BLOCK_SIZE];
    aes128::UCHAR key[AES_BLOCK_SIZE+1] = "AaBbCcDd1234!@#$";
    aes128::UCHAR raw_str[3][AES_BLOCK_SIZE] = {"admin", "abc123456", "123456cba"};
    aes128::UCHARPTR input_data = nullptr;
    aes128::UCHARPTR encrypt_data = nullptr;
    aes128::UCHARPTR decrypt_data = nullptr;

    resCode = aes.InitIv(iv);
    printf("iv init: ");
    for(int i = 0; i < AES_BLOCK_SIZE; i++) {
        printf("%02x", iv[i]);
    }
    printf("\n");
    memcpy(iv_dec, iv, AES_BLOCK_SIZE);

    for (int k = 0; k < 3; ++k) {
        aes.ZeroPaddingLength(raw_str[k]);
        input_data = (aes128::UCHARPTR)calloc(aes.GetDataLen()+1, sizeof(aes128::UCHARPTR));
        memcpy(input_data, raw_str[k], strlen((char *)raw_str[k]));
        //加密测试
        encrypt_data = (aes128::UCHARPTR)calloc(aes.GetDataLen()+1, sizeof(aes128::UCHARPTR));
        resCode = aes.AES_Encrypt(input_data, iv, key, encrypt_data);
        printf("\nencrypt_data: ");
        for(int i = 0; i < aes.GetDataLen(); i++) {
            printf("%02x", encrypt_data[i]);
        }
        printf("\n");
        //解密测试
        decrypt_data = (aes128::UCHARPTR)calloc(strlen((char *)encrypt_data), sizeof(aes128::UCHARPTR));
        resCode = aes.AES_Decrypt(encrypt_data, iv_dec, key, decrypt_data);
        // printf("\ndecrypt_data: ");
        // for(int i = 0; i < strlen((char *)encrypt_data); i++) {
        //     printf("%02x", decrypt_data[i]);
        // }
        printf("\ndecrypt_data: %s\n", (char *)decrypt_data);

        if (input_data != nullptr) {
            free(input_data);
            input_data = nullptr;
        }
        if (encrypt_data != nullptr) {
            free(encrypt_data);
            encrypt_data = nullptr;
        }
        if (decrypt_data != nullptr) {
            free(decrypt_data);
            decrypt_data = nullptr;
        }
    }
    return 0;
}

//g++ --std=c++11 test.cc -o test -L ../build/ -laes128 
//export LD_LIBRARY_PATH=/home/zzg/AES128/build/:$LD_LIBRARY_PATH