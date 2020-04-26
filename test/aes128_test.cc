#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <openssl/aes.h>

int main(int argc, char **argv)
{//由于与直接对接用的char，那么加解密要强制转换
    char Source[1024];
    char *InputData=NULL;
    char *EncryptData=NULL;
    char *DecryptData=NULL;
     
    unsigned char Key[AES_BLOCK_SIZE+1];    //建议用unsigned char
    unsigned char ivec[AES_BLOCK_SIZE];     //建议用unsigned char
    unsigned char ivecDec[AES_BLOCK_SIZE];
    AES_KEY AesKey;
     
    int DataLen=0,SetDataLen=0, i;
    int upCase, asciiCode;

    memset(Source, 0x00, sizeof(Source));
    strcpy(Source, "iot123456");  //要加密的数据
    DataLen = strlen(Source);

    memset(Key, 0x00, sizeof(Key));
    memcpy(Key, "AaBbCcDd1234!@#$", AES_BLOCK_SIZE);

 // set the encryption length
    SetDataLen = 0;
    if ((DataLen%AES_BLOCK_SIZE) == 0)
    {
        SetDataLen = DataLen;
    }
    else
    {
        SetDataLen = ((DataLen/AES_BLOCK_SIZE)+1) * AES_BLOCK_SIZE;
    }
    printf("SetDataLen:%d\n", SetDataLen);   //取16的倍数
     
    InputData = (char *)calloc(SetDataLen+1, sizeof(char));
    if(InputData == NULL)   //注意要SetDataLen+1
    {
        fprintf(stderr, "Unable to allocate memory for InputData\n");
        exit(-1);
    }
    memcpy(InputData, Source, DataLen);
    printf("InputData:%s\n", (char *)InputData);
     
    EncryptData = (char *)calloc(SetDataLen+1, sizeof(char));
    if(EncryptData == NULL) //注意要SetDataLen+1
    {
        fprintf(stderr, "Unable to allocate memory for EncryptData\n");
        exit(-1);
    }
     
    DecryptData = (char *)calloc(SetDataLen+1, sizeof(char));
    if(DecryptData == NULL) //注意要SetDataLen+1
    {
        fprintf(stderr, "Unable to allocate memory for DecryptData\n");
        exit(-1);
    }

    memset(&AesKey, 0x00, sizeof(AES_KEY));
    if(AES_set_encrypt_key(Key, 128, &AesKey) < 0)
    {//设置加密密钥
        fprintf(stderr, "Unable to set encryption key in AES...\n");
        exit(-1);
    }

    srand((int)time(0));
    for(i=0; i<AES_BLOCK_SIZE; i++)
    {//必须要有
        upCase = rand() % 3; //随机为2或1或0，为2就是数字，为1就是大写，为0就是小写 
        if (upCase == 2) {
            asciiCode = rand()%('9'-'0'+1) + '0';
        } else if (upCase == 1) {
            asciiCode = rand()%('Z'-'A'+1) + 'A'; 
        } else {
            asciiCode = rand()%('z'-'a'+1) + 'a';
        }
        
        ivec[i] = (unsigned char)asciiCode;
        // ivec[i] = 0;
    }
    printf("iv init: ");
    for(i=0; i<AES_BLOCK_SIZE; i++)
    {//必须要有
        printf("%02x", ivec[i]);
    }
    printf("\n");
    memcpy(ivecDec, ivec, AES_BLOCK_SIZE);
    //加密
    AES_cbc_encrypt((unsigned char *)InputData, (unsigned char *)EncryptData, 
        SetDataLen, &AesKey, ivec, AES_ENCRYPT);   
    printf("EncryptData:%s\n", (char *)EncryptData);

    memset(&AesKey, 0x00, sizeof(AES_KEY));
    if(AES_set_decrypt_key(Key, 128, &AesKey) < 0)
    {//设置解密密钥
        fprintf(stderr, "Unable to set encryption key in AES...\n");
        exit(-1);
    }
    printf("iv: ");
    for(i=0; i<AES_BLOCK_SIZE; i++)
    {//必须要有
        printf("%02x", ivec[i]);
        ivec[i] = 0;
    }
    printf("\n");
    //解密
    AES_cbc_encrypt((unsigned char *)EncryptData, (unsigned char *)DecryptData, 
        SetDataLen, &AesKey, ivecDec, AES_DECRYPT); 

    printf("DecryptData:%s\n", (char *)DecryptData);

    printf("iv: ");
    for(i=0; i<AES_BLOCK_SIZE; i++)
    {//必须要有
        printf("%02x", ivecDec[i]);
    }
    printf("\n");
    
    if(InputData != NULL)
    {
        free(InputData);
        InputData = NULL;
    }
     
    if(EncryptData != NULL)
    {
        free(EncryptData);
        EncryptData = NULL;
    }
     
    if(DecryptData != NULL)
    {
        free(DecryptData);
        DecryptData = NULL;
    }

    exit(0);
}

// RUN: g++ -std=c++11 aes128_test.cpp -o aes128_test -lm -lcrypto -ldl