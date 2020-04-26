#include "aes128.h"

using namespace std;

namespace aes128 {
    AES128::AES128():set_data_len_(0) {
        memset(&aes_key_, 0x00, sizeof(AES_KEY));
    }

    int AES128::InitIv(UCHARPTR iv) {
        int up_case(0), ascii_code(0);
        if (iv == nullptr) {
            return -1;
        }
        srand((int)time(0));
        for(int i = 0; i < AES_BLOCK_SIZE; i++) {
            up_case = rand() % 3; //随机为2或1或0，为2就是数字，为1就是大写，为0就是小写 
            if (up_case == 2) {
                ascii_code = rand()%('9'-'0'+1) + '0';
            } else if (up_case == 1) {
                ascii_code = rand()%('Z'-'A'+1) + 'A'; 
            } else {
                ascii_code = rand()%('z'-'a'+1) + 'a';
            }
            
            iv[i] = (unsigned char)ascii_code;
            // iv[i] = 0;
        }
        return 0;
    }

    int AES128::ZeroPaddingLength(UCHARPTR raw_str) {
        if (raw_str == nullptr) {
            return -1;
        }
        int data_len = 0;
        while (*(raw_str++)) {
            ++data_len;
        }
        if ((data_len%AES_BLOCK_SIZE) == 0) {
            set_data_len_ = data_len;
        } else {
            set_data_len_ = ((data_len/AES_BLOCK_SIZE)+1) * AES_BLOCK_SIZE;
        }
        return 0;
    }

    int AES128::AES_Encrypt(UCHARPTR raw_str, UCHARPTR iv, UCHARPTR key, UCHARPTR encrypt_data) {
        if (raw_str == nullptr || iv == nullptr || key == nullptr || encrypt_data == nullptr) {
            return -1;
        }
        // printf("iv: ");
        // for(int i = 0; i < AES_BLOCK_SIZE; i++) {
        //     printf("%02x", iv[i]);
        // }
        // printf("\n");
        //设置加密密钥
        memset(&aes_key_, 0x00, sizeof(AES_KEY));
        if (AES_set_encrypt_key(key, 128, &aes_key_) < 0) {
            std::cout << "Unable to set encryption key in AES..." << std::endl;
            return -1;
        }
        // printf("raw_str: ");
        // for(int i = 0; i < AES_BLOCK_SIZE; i++) {
        //     printf("%02x", raw_str[i]);
        // }
        // printf("\n");
        // printf("key: ");
        // for(int i = 0; i < AES_BLOCK_SIZE; i++) {
        //     printf("%02x", key[i]);
        // }
        //加密
        AES_cbc_encrypt(raw_str, encrypt_data, set_data_len_, &aes_key_, iv, AES_ENCRYPT);   
        return 0;
    }
    
    int AES128::AES_Decrypt(UCHARPTR raw_str, UCHARPTR iv, UCHARPTR key, UCHARPTR decrypt_data) {
        if (raw_str == nullptr || iv == nullptr || key == nullptr || decrypt_data == nullptr) {
            return -1;
        }
        // printf("iv: ");
        // for(int i = 0; i < AES_BLOCK_SIZE; i++) {
        //     printf("%02x", iv[i]);
        // }
        // printf("\n");
        //设置解密密钥
        memset(&aes_key_, 0x00, sizeof(AES_KEY));
        if(AES_set_decrypt_key(key, 128, &aes_key_) < 0) {
            std::cout << "Unable to set decryption key in AES..." << std::endl;
            return -1;
        }
        // printf("raw_str: ");
        // for(int i = 0; i < AES_BLOCK_SIZE; i++) {
        //     printf("%02x", raw_str[i]);
        // }
        // printf("\n");
        // printf("key: ");
        // for(int i = 0; i < AES_BLOCK_SIZE; i++) {
        //     printf("%02x", key[i]);
        // }
        //解密
        AES_cbc_encrypt(raw_str, decrypt_data, set_data_len_, &aes_key_, iv, AES_DECRYPT); 
        return 0;
    }
}