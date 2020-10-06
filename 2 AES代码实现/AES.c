#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include<time.h>
typedef enum
{
    false = 0,
    true  = 1
} bool;
const char* AES_MODE[] = {"ECB","CBC","CFB","OFB"};
unsigned char w[][4][4];
char* plainfile = NULL;
char* keyfile = NULL;
char* vifile = NULL;
char* mode = NULL;
char* cipherfile = NULL;
typedef unsigned char uint8_t; //�޷���8λ���������ͣ���Ϊһ���ֽ�
uint8_t* plaintext = NULL;
uint8_t* keytext = NULL;
uint8_t* vitext = NULL;
uint8_t* ciphertext = NULL;
const uint8_t Rcon[10]={0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
const unsigned char S_Box[256] = {   //S��
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};
const unsigned char SR_Box[256] = {  //��S��
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

//�������������ʾ�����˳�����
void print_usage() {
    printf("\n�Ƿ�����,֧�ֵĲ��������£�\n-p plainfile ָ�������ļ���λ�ú�����\n-k keyfile  ָ����Կ�ļ���λ�ú�����\n-v vifile  ָ����ʼ�������ļ���λ�ú�����\n-m mode  ָ�����ܵĲ���ģʽ(ECB,CBC,CFB,OFB)\n-c cipherfile ָ�������ļ���λ�ú����ơ�\n");
    exit(-1);
}

//��ȡ�ļ����ڴ棬ͬʱ���ַ���4e�� ת��һ���ֽ�0x4e
bool readfile2memory(const char* filename, uint8_t** memory) {
	int i;
	int size;
	FILE* fp = NULL;
	fp = fopen(filename, "r");
	if (fp == NULL) {
		return false;
	}
	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	uint8_t* tmp = malloc(size);
	memset(tmp, 0, size);

	fread(tmp, size, 1, fp);
	if (ferror(fp)) {
		printf("��ȡ%s�����ˣ�\n", filename);
		fclose(fp);
		return false;
	}
	else {
		fclose(fp);
	}

	*memory = malloc(size / 2);
	memset(*memory, 0, size / 2);
	uint8_t parsewalker[3] = { 0 };
	//printf("readfile2memory debug info:");
	for (i = 0; i < size; i += 2) {
		parsewalker[0] = tmp[i];
		parsewalker[1] = tmp[i + 1];
		(*memory)[i / 2] = strtol(parsewalker, 0, 16);
		//printf("%c", (*memory)[i / 2]);
	}
	//printf("\n");
	free(tmp);
	return true;
}

//ת��Ϊ״̬����
void stateMatrix(uint8_t state[4][4], const uint8_t *input) { 
    int i,j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            state[j][i] = *input++;  //��16λ������״̬��������Ϊ˳��
        }
    }
}

//״̬����ת��Ϊ�������
void storeStateMatrix(uint8_t *output,uint8_t state[4][4]) { 
    int i,j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            *output++ = state[j][i];
        }
    }
}

//�ֽ��滻
void ByteSub(uint8_t state[4][4],const unsigned char *Table){
    int i,j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            state[i][j] = Table[state[i][j]]; //ֱ��ʹ��ԭʼ�ֽ���ΪS/��S�������±�
        }
    }
}

//����λ
void ShiftRows(uint8_t state[4][4]){ 
    int i,j;
    uint8_t temp[4][4];
    for(i=0;i<4;i++){
        for(j=0;j<4;j++){
           temp[i][j]=state[i][j];
        }
    }
    for(i=0;i<4;i++){
        for(j=0;j<4;j++){
            state[i][j]=temp[i][(j+i)%4]; //��ѭ��������Ӧ��λ��
        }
    }
}

//������λ
void InShiftRows(uint8_t state[4][4]){  
    int i,j;
    uint8_t temp[4][4];
    for(i=0;i<4;i++){
        for(j=0;j<4;j++){
           temp[i][j]=state[i][j];
        }
    }
    for(i=0;i<4;i++){
        for(j=0;j<4;j++){
            state[i][j]=temp[i][(4+j-i)%4]; //��ѭ��������Ӧ��λ��
        }
    }
}

//X�˷�
uint8_t XTIME(uint8_t x) {  
	return ((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));  //���λ��1������һλ��ͬʱ���0x1B
}

//����ʽ���
uint8_t multiply(uint8_t a, uint8_t b) {
	unsigned char temp[8] = { a };
    uint8_t tempmultiply = 0x00;
	int i;
	for (i = 1; i < 8; i++) {
		temp[i] = XTIME(temp[i - 1]);  //�õ�һ������8���ַ�������
	}
	tempmultiply = (b & 0x01) * a;
	for (i = 1; i <= 7; i++) {
		tempmultiply ^= (((b >> i) & 0x01) * temp[i]);  //b����һλ��0x01�����㣬�ֱ��8���ַ���������
	}
	return tempmultiply;
}

//�л���
void MixColumns(uint8_t state[4][4]){
    int i,j;
    uint8_t temp[4][4];
    uint8_t M[4][4]={
        {0x02, 0x03, 0x01, 0x01},
        {0x01, 0x02, 0x03, 0x01},
        {0x01, 0x01, 0x02, 0x03},
        {0x03, 0x01, 0x01, 0x02}
    };
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j){
            temp[i][j] = state[i][j];
        }
    }

    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {  //X�˷�
            state[i][j] = multiply(M[i][0], temp[0][j]) ^ multiply(M[i][1], temp[1][j])
                        ^ multiply(M[i][2], temp[2][j]) ^ multiply(M[i][3], temp[3][j]);
        }
    }
}

//���л���
void InMixColumns (uint8_t state[4][4]){
    int i,j;
    uint8_t temp[4][4];
    uint8_t M[4][4]={
        {0x0E, 0x0B, 0x0D, 0x09},
        {0x09, 0x0E, 0x0B, 0x0D},
        {0x0D, 0x09, 0x0E, 0x0B},
        {0x0B, 0x0D, 0x09, 0x0E}};  //�л�Ͼ���������
    for(i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j){
            temp[i][j] = state[i][j];
        }
    }

    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            state[i][j] = multiply(M[i][0], temp[0][j]) ^ multiply(M[i][1], temp[1][j])
                        ^ multiply(M[i][2], temp[2][j]) ^ multiply(M[i][3], temp[3][j]);
        }
    }
}

//����Կ��
void AddRoundKey(uint8_t state[4][4],uint8_t W[4][4]){  
    int i,j;
    for(i=0;i<4;i++){
        for(j=0;j<4;j++){
            state[j][i]^=W[j][i];
        }
    }
}

//����Կ
static void KeyExpansion(const uint8_t *key,unsigned char w[][4][4]){
    int i,j,r;
    for(i=0;i<4;i++){
        for(j=0;j<4;j++){
            w[0][i][j]=key[i+j*4]; //w[0]-w[3]����һ����Ϊw[0],w[0][j][i]��Ӧw[i]
        }
    }
    for(i=1; i<=10; i++)
	{
		for(j=0; j<4; j++)
		{
			unsigned char t[4];
			for(r=0; r<4; r++)
			{
				t[r] = j ? w[i][r][j-1] : w[i-1][r][3]; 
			}
			if(j == 0)
			{
				unsigned char temp = t[0];
				for(r=0; r<3; r++)
				{
					t[r] = S_Box[t[(r+1)%4]]; //ѭ������һ���ֽڣ���ֻ��ҪS���滻ʱ��Ӧλ�ü�һ
				}
				t[3] = S_Box[temp]; //��Ϊ��ѭ����λ��t[3]Ϊt[0]��Ӧ��
				t[0] ^= Rcon[i-1]; //
			}
			for(r=0; r<4; r++)
			{
				w[i][r][j] = w[i-1][r][j] ^ t[r];
			}
		}
	}
}

//����һ������
void Table_copy(uint8_t* output,uint8_t* input,int num){
    int i;
    for(i=0;i<num;i++){
        output[i]=input[i];
    }
}

//���
void Xor(uint8_t* a,uint8_t* b,int num){
    int i;
    for(i=0;i<num;i++){
        a[i]^=b[i];
    }
}

//��ѭ����λ
void RotateL(uint8_t* output,uint8_t* input,int len,int num){  
	int i;
	for(i=0;i<len;i++){
		output[i]=input[(i+num)%len];
	}
}

//�����ݿ����
void AES(uint8_t *output,const uint8_t *key_in,const uint8_t *input){
    int i,j,k;
    uint8_t state[4][4];
    KeyExpansion(key_in,w);
    stateMatrix(state,input);  //ת��Ϊ״̬����
    AddRoundKey(state,w[0]);  //��ʼ����Կ��
    for(i=1;i<=10;i++){
        ByteSub(state,S_Box);
        ShiftRows(state);
        if(i!=10)
            MixColumns(state);
        AddRoundKey(state,w[i]);
    }
    storeStateMatrix(output,state);
}

//�����ݿ����
void AES_re(uint8_t *output,uint8_t *key_in, uint8_t*input){
    int i,j,k;
    uint8_t state[4][4];
    KeyExpansion(key_in,w);
    stateMatrix(state,input);  //ת��Ϊ״̬����
    AddRoundKey(state,w[10]);  //��ʼ����Կ��
    for(i=9;i>=0;i--){
        InShiftRows(state);
        ByteSub(state,SR_Box);
        AddRoundKey(state,w[i]);
        if(i!=0)
            InMixColumns(state);
    }
    storeStateMatrix(output,state);
}

//ECB����
void ECB(const uint8_t* plaintext, const uint8_t* keytext, uint8_t** ciphertext,const int length) {
	uint8_t plain_set[16];  //����һ��128λ������
	uint8_t cipher_set[16];  //����һ��128λ������
	int num,i,j;
	uint8_t* cipher;
	*ciphertext=malloc(length+1); //��̬�����ڴ棬��ס��1����Ҫ��NULL��β
	memset(*ciphertext,0,length+1);
	cipher=*ciphertext;

	num=length/16;   //������������м���
	for(i=0;i<num;i++){
		for(j=0;j<16;j++){
            plain_set[j]=plaintext[j+i*16];    //����128λ������
		}
		AES(cipher_set,keytext,plain_set);
		for(j=0;j<16;j++){
			cipher[i*16+j]=cipher_set[j];
		}
	}
	cipher[length]='\0';  //��NULL��β
}

//ECB����
void ECB_decrypt(uint8_t** plaintext,const uint8_t* ciphertext,const uint8_t* keytext,const int length){
    uint8_t plain_set[16];  //����һ��128λ������
	uint8_t cipher_set[16];  //����һ��128λ������
	int num,i,j;
	uint8_t* plain;
	*plaintext=malloc(length+1); //��̬�����ڴ棬��ס��1����Ҫ��NULL��β
	memset(*plaintext,0,length+1);
	plain=*plaintext;

	num=length/16;   //������������м���
	for(i=0;i<num;i++){
		for(j=0;j<16;j++){
            cipher_set[j]=ciphertext[j+i*16];    //����128λ������
		}
		AES_re(plain_set,keytext,cipher_set);
		for(j=0;j<16;j++){
			plain[i*16+j]=plain_set[j];
		}
	}
    plain[length]='\0';  //��NULL��β
}

//CBC����
void CBC(const uint8_t* plaintext, const uint8_t* keytext, const uint8_t* vitext, uint8_t** ciphertext,const int length) {
	uint8_t plain_set[16];
    uint8_t cipher_set[16];
    uint8_t iv_temp[16];
	int num,i,j,t;
    uint8_t* cipher;
	*ciphertext=malloc(length+1);
	memset(*ciphertext,0,length+1);
    cipher=*ciphertext;
	num=length/16;
    Table_copy(iv_temp,vitext,16);
	for(i=0;i<num;i++){
		for(j=0;j<16;j++){
            plain_set[j]=plaintext[j+i*16];
		}
		Xor(plain_set,iv_temp,16); //��һ�����������Ľ�����򣬺���ǰһ�����ķ����뵱ǰ���Ľ������
		AES(cipher_set,keytext,plain_set);  //���ܵ����ķ���һ
		Table_copy(iv_temp,cipher_set,16);
		for(j=0;j<16;j++){
            cipher[j+i*16]=cipher_set[j]; //16��������ʾ�����Ĵ��ݸ�cipher
		}
	}
	cipher[length]='\0';  //��NULL��β
}

//CBC����
void CBC_decrypt(uint8_t** plaintext,const uint8_t* ciphertext,const uint8_t* keytext,const uint8_t* vitext,const int length){
    uint8_t plain_set[16];
    uint8_t cipher_set[16];
    uint8_t iv_temp[16];
	int num,i,j;
	uint8_t *plain;
	*plaintext=malloc(length+1); //��̬�����ڴ棬��ס��1����Ҫ��NULL��β
	memset(*plaintext,0,length+1);
	plain=*plaintext;
	Table_copy(iv_temp,vitext,16);
    num=length/16;
    for(i=0;i<num;i++){
        for(j=0;j<16;j++){
            cipher_set[j]=ciphertext[i*16+j];
        }
        AES_re(plain_set,keytext,cipher_set);
        Xor(plain_set,iv_temp,16);
        Table_copy(iv_temp,cipher_set,16); //��ǰ���ķ�������һ�����ķ�����ܺ�������
        for(j=0;j<16;j++){
            plain[j+i*16]=plain_set[j];
            //printf("%.2x",plain[j+i*16]);
        }
    }
    plain[length]='\0';  //��NULL��β
}

//CFB����
void CFB(const uint8_t* plaintext, const uint8_t* keytext, const uint8_t* vitext, uint8_t** ciphertext,int length) {
	uint8_t plain_set[1];  //����8λ�����ģ���һ��һ������
    uint8_t cipher_set[1]={0};  //����8λ������
    uint8_t hex_register[16];
    uint8_t iv_temp[16],hex_temp1[16],hex_temp2[1];
	int num,i,j;
	uint8_t* cipher;
	*ciphertext=malloc(length+1); //��̬�����ڴ棬��ס��1����Ҫ��NULL��β
	memset(*ciphertext,0,length+1);
	cipher=*ciphertext;
	num=length;      //Ϊ8λCFBģʽ
	Table_copy(hex_temp1,vitext,16);
	for(i=0;i<num;i++){
        AES(hex_register,keytext,hex_temp1);
        Table_copy(cipher_set,hex_register,1);  //ѡ����ߵ�8λ����һ���ֽ�
        plain_set[0]=plaintext[i];
		Xor(cipher_set,plain_set,1);
		Table_copy(hex_temp2,cipher_set,1);
        cipher[i]=cipher_set[0]; //16��������ʾ�����Ĵ��ݸ�cipher
		RotateL(iv_temp,hex_temp1,16,1);  //��ѭ����λ
		Table_copy(hex_temp1,iv_temp,16);
        hex_temp1[15]=hex_temp2[0];  //���Ĵ����ұ�8λ���������
	}
	cipher[length]='\0';  //��NULL��β
}

//CFB����
void CFB_decrypt(uint8_t** plaintext,const uint8_t* ciphertext,const uint8_t* keytext,const uint8_t* vitext,const int length){
    uint8_t plain_set[1];  //����8λ�����ģ���һ��һ������
    uint8_t cipher_set[1]={0};  //����8λ������
    uint8_t hex_register[16];
    uint8_t iv_temp[16],hex_temp1[16],hex_temp2[1];
	int num,i,j;
	uint8_t *plain;
	*plaintext=malloc(length+1); //��̬�����ڴ棬��ס��1����Ҫ��NULL��β
	memset(*plaintext,0,length+1);
	plain=*plaintext;
	Table_copy(hex_temp1,vitext,16);
    num=length;
    for(i=0;i<num;i++){
        AES(hex_register,keytext,hex_temp1);
        Table_copy(plain_set,hex_register,1);  //ѡ����ߵ�8λ
        cipher_set[0]=ciphertext[i];
		Xor(plain_set,cipher_set,1);
		Table_copy(hex_temp2,cipher_set,1);
        plain[i]=plain_set[0];
		RotateL(iv_temp,hex_temp1,16,1);  //��ѭ����λ
		Table_copy(hex_temp1,iv_temp,16);
        hex_temp1[15]=hex_temp2[0];  //���Ĵ����ұ�8λ���������
	}
	plain[length]='\0';  //��NULL��β
}

//OFB����
void OFB(const uint8_t* plaintext, const uint8_t* keytext, const uint8_t* vitext, uint8_t** ciphertext,const int length) {
	uint8_t plain_set[1];  //����8λ�����ģ���һ��һ������
    uint8_t cipher_set[16],temp_cipher[1];  //����8λ������
    uint8_t iv_temp[16],hex_temp1[16],hex_temp2[16];
	int num,i,j;
	uint8_t* cipher;
	*ciphertext=malloc(length+1);
    memset(*ciphertext,0,length+1);
    cipher=*ciphertext;
	num=length;//8λOFBģʽ
	Table_copy(iv_temp,vitext,16);
	Table_copy(hex_temp1,vitext,16);
	for(i=0;i<num;i++){
        AES(cipher_set,keytext,iv_temp);  //�Ĵ������ݽ��м���
		Table_copy(temp_cipher,cipher_set,1); //���ܺ��ǰ��λ
		RotateL(hex_temp2,hex_temp1,16,1);  //��ѭ����λ
        hex_temp2[15]=temp_cipher[0];  //���Ĵ����ұ�8λ���������
		Table_copy(hex_temp1,hex_temp2,16);  //hex_temp1�������ÿ�μĴ���ƫ�Ʋ�λ֮�������
        Table_copy(iv_temp,hex_temp1,16);
        plain_set[0]=plaintext[i];
		Xor(temp_cipher,plain_set,1);
        cipher[i]=temp_cipher[0]; //16��������ʾ�����Ĵ��ݸ�cipher
	}
	cipher[length]='\0';  //��NULL��β
}

//OFB����
void OFB_decrypt(uint8_t** plaintext,const uint8_t* ciphertext,const uint8_t* keytext,const uint8_t* vitext,const int length){
    uint8_t plain_set[16],temp_plain[1];  //����8λ�����ģ���һ��һ������
    uint8_t cipher_set[1]={0};  //����8λ������
    uint8_t iv_temp[16],hex_temp1[16],hex_temp2[16];
	int num,i,j;
	uint8_t *plain;
	*plaintext=malloc(length+1); //��̬�����ڴ棬��ס��1����Ҫ��NULL��β
	memset(*plaintext,0,length+1);
	plain=*plaintext;
	Table_copy(hex_temp1,vitext,16);
    num=length;
    Table_copy(iv_temp,vitext,16);
	for(i=0;i<num;i++){
        AES(plain_set,keytext,iv_temp);  //�Ĵ������ݽ��м���
		Table_copy(temp_plain,plain_set,1); //���ܺ��ǰ��λ
		RotateL(hex_temp2,hex_temp1,16,1);  //��ѭ����λ
        hex_temp2[15]=temp_plain[0];  //���Ĵ����ұ�8λ���������
		Table_copy(hex_temp1,hex_temp2,16);  //hex_temp1�������ÿ�μĴ���ƫ�Ʋ�λ֮�������
        Table_copy(iv_temp,hex_temp1,16);
        cipher_set[0]=ciphertext[i];
		Xor(temp_plain,cipher_set,1);
        plain[i]=temp_plain[0];
	}
	plain[length]='\0';  //��NULL��β*/
}

//����5MB������ݣ�20�ּӽ��ܣ������ٶȲ���
void speedTest(int choice) {
		uint8_t* key_test=NULL;
		uint8_t* plain_test=NULL;
		//uint8_t* plain_test1=NULL;
		uint8_t* cipher_test=NULL;
		uint8_t* vi_test=NULL;
		unsigned char num;
		bool read;
		int j,k,t,m,u;
		int test_len;
		double size;
		clock_t start, stop; //clock_tΪclock()�������صı�������
		double duration;
		double v;
		test_len=5*pow(2,20);  //��Ҫ����5MB�������������
		plain_test=(uint8_t*)malloc(test_len*sizeof(uint8_t)+1);
		for(k=0;k<test_len;k++){
			num = rand()%16;
			if(num>=5){
				num = num -5 +'A';
			}
			else{
				num = num + '0';
			}
			plain_test[k]=num;
			//printf("%.2x  ",plain_test[k]);
		}
		plain_test[k]='\0';
		/*plain_test=malloc((i/2)+1);
		memset(plain_test,0,(i/2)+1);
        uint8_t parsewalker[3] = { 0 };
        for (u= 0; u < i; u += 2) {
            parsewalker[0] = plain_test1[u];
            parsewalker[1] = plain_test1[u+ 1];
            plain_test[u / 2] = strtol(parsewalker, 0, 16);
        }*/
		size=(double)(test_len/(1024*1024));
		//printf("�������ݳɹ������ݴ�С%.2fMB\n",size);
		read= readfile2memory("AES_key.txt", &key_test);
		read= readfile2memory("AES_iv.txt", &vi_test);
		switch(choice){
			case 1:
				printf("ECB 20 rounds -Decrypt Speed Test:");
				start=clock();
    			for(k=1;k<21;k++){
                    printf("\nNo.%d Encryption done.  ",k);
                    ECB(plain_test,key_test,&cipher_test,test_len);
                    /*printf("\nǰ32�ֽ�����Ϊ��");
                    for(m=0;m<32;m++){
                        printf("%.2X",cipher_test[m]);
                    }
                    printf("\n");*/
                    ECB_decrypt(&plain_test,cipher_test,key_test,test_len);
                    printf("No.%d Decryption done.",k);
                    /*for(m=0;m<32;m++){
                        printf("%.2X",plain_test[m]);
                    }*/
				}
    			stop=clock();
    			duration=(double)(stop-start); //CLK_TCKΪclock()������ʱ�䵥λ����ʱ�Ӵ��
    			printf("\n20 rounds ALL DONE.");
    			printf("\nThe time spent is��%.4fms\n",duration);
    			v=(double)(size*20*2/(duration/1000));
    			printf("\nThe speed is��%.4fMByte/s\n",v);
    			break;
    		case 2:
    			printf("CBC 20 rounds Encrypt-Decrypt Speed Test:");
				start=clock();
    			for(k=1;k<21;k++){
                    printf("\nNo.%d Encryption done.  ",k);
                    CBC(plain_test,key_test,vi_test,&cipher_test,test_len);
                    /*printf("\nǰ32�ֽ�����Ϊ��");
                    for(m=0;m<32;m++){
                        printf("%.2X",cipher_test[m]);
                    }
                    printf("\n");*/
                    CBC_decrypt(&plain_test,cipher_test,key_test,vi_test,test_len);
                    printf("No.%d Decryption done.",k);
                    /*for(m=0;m<32;m++){
                        printf("%.2X",plain_test[m]);
                    }*/
				}
    			stop=clock();
    			duration=(double)(stop-start); //CLK_TCKΪclock()������ʱ�䵥λ����ʱ�Ӵ��
    			printf("\n20 rounds ALL DONE.");
    			printf("\nThe time spent is��%.4fms\n",duration);
    			v=(double)(size*20*2/(duration/1000));
    			printf("\nThe speed is��%.4fMByte/s\n",v);
    			break;
    		case 3:
    			printf("CFB 20 rounds Encrypt-Decrypt Speed Test:");
				start=clock();
    			for(k=1;k<21;k++){
                    printf("\nNo.%d Encryption done.  ",k);
                    CFB(plain_test,key_test,vi_test,&cipher_test,test_len);
                    /*printf("\nǰ32�ֽ�����Ϊ��");
                    for(m=0;m<32;m++){
                        printf("%.2X",cipher_test[m]);
                    }
                    printf("\n");*/
                    CFB_decrypt(&plain_test,cipher_test,key_test,vi_test,test_len);
                    printf("No.%d Decryption done.",k);
                    /*for(m=0;m<32;m++){
                        printf("%.2X",plain_test[m]);
                    }*/
				}
    			stop=clock();
    			duration=(double)(stop-start); //CLK_TCKΪclock()������ʱ�䵥λ����ʱ�Ӵ��
    			printf("\n20 rounds ALL DONE.");
    			printf("\nThe time spent is��%.4fms\n",duration);
    			v=(double)(size*20*2/(duration/1000));
    			printf("\nThe speed is��%.4fMByte/s\n",v);
    			break;
    		case 4:
    			   	printf("OFB 20 rounds Encrypt-Decrypt Speed Test:");
					start=clock();
    				for(k=1;k<21;k++){
                        printf("\nNo.%d Encryption done.  ",k);
                        OFB(plain_test,key_test,vi_test,&cipher_test,test_len);
                        /*printf("\nǰ32�ֽ�����Ϊ��");
                        for(m=0;m<32;m++){
                            printf("%.2X",cipher_test[m]);
                        }
                        printf("\n");*/
                        OFB_decrypt(&plain_test,cipher_test,key_test,vi_test,test_len);
                        printf("No.%d Decryption done.",k);
                        /*for(m=0;m<32;m++){
                            printf("%.2X",plain_test[m]);
                        }*/
					}
   				stop=clock();
    			duration=(double)(stop-start); //CLK_TCKΪclock()������ʱ�䵥λ����ʱ�Ӵ��
    			printf("\n20 rounds ALL DONE.");
    			printf("\nThe time spent is��%.4fms\n",duration);
    			v=(double)(size*20*2/(duration/1000));
    			printf("\nThe speed is��%.4fMByte/s\n",v);
    			break;
    		default:
    			printf("����");
		}
}

//���������������
int main(int argc, char** argv) {
    int s,i,count;
    bool read_result;

	if (argc % 2 == 0) {
		print_usage();
	}
	for (i = 1; i < argc; i += 2) {
		if (strlen(argv[i]) != 2) {
			print_usage();
		}
		switch (argv[i][1]) {
		case 'p':
			plainfile = argv[i + 1];
			break;
		case 'k':
			keyfile = argv[i + 1];
			break;
		case 'v':
			vifile = argv[i + 1];
			break;
		case 'm':
			if (strcmp(argv[i + 1], AES_MODE[0]) != 0 && strcmp(argv[i + 1], AES_MODE[1]) != 0 && strcmp(argv[i + 1], AES_MODE[2]) != 0 && strcmp(argv[i + 1], AES_MODE[3]) != 0) {
				print_usage();
			}
			mode = argv[i + 1];
			break;
		case 'c':
			cipherfile = argv[i + 1];
			break;
		default:
			print_usage();
		}
	}
	if (plainfile == NULL || keyfile == NULL || mode == NULL || cipherfile == NULL) {
		print_usage();
	}
	if (strcmp(mode, "ECB") != 0 && vifile == NULL) {
		print_usage();
	}

	read_result = readfile2memory(plainfile, &plaintext);
	if (read_result == false) {
		printf("��ȡ�����ļ�ʧ�ܣ�����·�����ļ��Ƿ����\n");
		exit(-1);
	}
	read_result = readfile2memory(keyfile, &keytext);
	if (read_result == false) {
		printf("��ȡ��Կ�ļ�ʧ�ܣ�����·�����ļ��Ƿ����\n");
		exit(-1);
	}
	if (strcmp(mode, "ECB") != 0) {
		read_result = readfile2memory(vifile, &vitext);
		if (read_result == false) {
			printf("��ȡ��ʼ�����ļ�ʧ�ܣ�����·�����ļ��Ƿ����\n");
			exit(-1);
		}
	}
	int len=32; //�ֽ���
	if (strcmp(mode, "ECB") == 0) {
		ECB(plaintext, keytext, &ciphertext,len);
		ECB_decrypt(&plaintext,ciphertext,keytext,len);//���Խ���
		/*printf("���ܳ�������Ϊ%s\n",plaintext);
		printf("16���Ʊ�ʾΪ��");
		for(s=0;s<32;s++){
            printf("%.2X",plaintext[s]);
        }*/
	}
	else if (strcmp(mode, "CBC") == 0) {
		CBC(plaintext, keytext, vitext, &ciphertext,len);
		CBC_decrypt(&plaintext,ciphertext, keytext, vitext,len);
		/*printf("���ܳ�������Ϊ%s\n",plaintext);
		printf("16���Ʊ�ʾΪ��");
		for(s=0;s<32;s++){
            printf("%.2X",plaintext[s]);
        }*/
	}
	else if (strcmp(mode, "CFB") == 0) {
		CFB(plaintext, keytext, vitext, &ciphertext,len);
		CFB_decrypt(&plaintext,ciphertext, keytext, vitext,len);
		/*printf("���ܳ�������Ϊ%s\n",plaintext);
		printf("16���Ʊ�ʾΪ��");
		for(s=0;s<32;s++){
            printf("%.2X",plaintext[s]);
        }*/

	}
	else if (strcmp(mode, "OFB") == 0) {
		OFB(plaintext, keytext, vitext, &ciphertext,len);
		OFB_decrypt(&plaintext, ciphertext,keytext, vitext,len);
		/*printf("���ܳ�������Ϊ%s\n",plaintext);
		printf("16���Ʊ�ʾΪ��");
		for(s=0;s<32;s++){
            printf("%.2X",plaintext[s]);
        }*/

	}
	else {
		//��Ӧ���ܵ�������
		printf("�������󣡣���\n");
		exit(-2);
	}

	//printf("\n���ܳ��������ģ�16���Ʊ�ʾΪ��: ");
    /*for(int k=0;k<32;k++){
        printf("%.2X",ciphertext[k]);
    }*/
	count = 32;
	uint8_t* cipherhex = malloc(count * 2+1);
	memset(cipherhex, 0, count * 2+1);

	for (i = 0; i < count; i++) {
		sprintf(cipherhex + i * 2, "%.2X", ciphertext[i]);
	}
	FILE* fp = fopen(cipherfile, "w");
	if (fp == NULL) {
		printf("�ļ� %s ��ʧ��,����", cipherfile);
		exit(-1);
	}

	int writecount = fwrite(cipherhex, count * 2, 1, fp);
	if (writecount != 1) {
		printf("д���ļ����ֹ��ϣ������³��ԣ�");
		fclose(fp);
		exit(-1);
	}
	/*else{
		printf("\nAlready written to the file.\n\n");
	}*/
	fclose(fp);
	if (strcmp(mode, "ECB") == 0) {
		speedTest(1);
	}
	else if (strcmp(mode, "CBC") == 0) {
		speedTest(2);
	}
	else if (strcmp(mode, "CFB") == 0) {
		speedTest(3);
	}
	else if (strcmp(mode, "OFB") == 0) {
		speedTest(4);
	}
	else {
		printf("�������󣡣���\n");
		exit(-2);
	}
	return 0;
}
