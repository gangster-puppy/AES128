#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/aes.h>
#include <iostream>

namespace aes128 {
using UCHAR = unsigned char;
using UCHARPTR = unsigned char*;

class AES128 {
  public:
    AES128 ();
    int InitIv(UCHARPTR iv);   //随机初始化偏移量iv
    int ZeroPaddingLength(UCHARPTR raw_str);    //设置加解密字符串长度，非16字节倍数则用0补齐
    inline int GetDataLen() {return set_data_len_;}
    // UCHARPTR GetIv();
    // void SetIv(UCHARPTR iv);

    /*AES加密：
    入参：明文、偏移量、加密秘钥
    出参：密文
    */
    int AES_Encrypt(UCHARPTR raw_str, UCHARPTR iv, UCHARPTR key, UCHARPTR encrypt_data);

    /*AES解密：
    入参：密文、偏移量、解密秘钥
    出参：明文
    */
    int AES_Decrypt(UCHARPTR raw_str, UCHARPTR iv, UCHARPTR key, UCHARPTR decrypt_data);

  private:
    // UCHARPTR iv_;
    // UCHARPTR key_;
    AES_KEY aes_key_;
    int set_data_len_;
};
}