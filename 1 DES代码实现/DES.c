#define _CRT_SECURE_NO_WARNINGS
#include<stdio.h>
#include<string.h>
#include<stdlib.h>

typedef enum
{
    false = 0,
    true  = 1
} bool;
const char* DES_MODE[] = {"ECB","CBC","CFB","OFB"};
const int IP_Table[64]={ 58,50,42,34,26,18,10, 2,60,52,44,36,28,20,12, 4, 62,54,46,38,30,22,14, 6,64,56,48,40,32,24,16, 8, 57,49,41,33,25,17, 9, 1,59,51,43,35,27,19,11, 3, 61,53,45,37,29,21,13, 5,63,55,47,39,31,23,15, 7 };
const int IPR_Table[64]={ 40, 8,48,16,56,24,64,32,39, 7,47,15,55,23,63,31, 38, 6,46,14,54,22,62,30,37, 5,45,13,53,21,61,29, 36, 4,44,12,52,20,60,28,35, 3,43,11,51,19,59,27, 34, 2,42,10,50,18,58,26,33, 1,41, 9,49,17,57,25 };
const int E_Table[48]={ 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9,10,11,12,13, 12,13,14,15,16,17, 16,17,18,19,20,21, 20,21,22,23,24,25, 24,25,26,27,28,29, 28,29,30,31,32, 1 };
const int PC1_Table[56]={ 57,49,41,33,25,17, 9, 1,58,50,42,34,26,18, 10, 2,59,51,43,35,27,19,11, 3,60,52,44,36, 63,55,47,39,31,23,15, 7,62,54,46,38,30,22, 14, 6,61,53,45,37,29,21,13, 5,28,20,12, 4 };
const int Move_Table[16]={ 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
const int PC2_Table[48]={ 14,17,11,24, 1, 5, 3,28,15, 6,21,10, 23,19,12, 4,26, 8,16, 7,27,20,13, 2, 41,52,31,37,47,55,30,40,51,45,33,48, 44,49,39,56,34,53,46,42,50,36,29,32 };
const int S_Box[8][4][16]={ //S1
 14, 4,13, 1, 2,15,11, 8, 3,10, 6,12, 5, 9, 0, 7, 0,15, 7, 4,14, 2,13, 1,10, 6,12,11, 9, 5, 3, 8, 4, 1,14, 8,13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0, 15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13,
 //S2
 15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10, 3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5, 0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15, 13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9,
 //S3
 10, 0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1, 13, 6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7, 1,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11, 5, 2,12,
 //S4
 7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4,15, 13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14, 9, 10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8, 4, 3,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2,14,
 //S5
 2,12, 4, 1, 7,10,11, 6, 8, 5, 3,15,13, 0,14, 9, 14,11, 2,12, 4, 7,13, 1, 5, 0,15,10, 3, 9, 8, 6, 4, 2, 1,11,10,13, 7, 8,15, 9,12, 5, 6, 3, 0,14, 11, 8,12, 7, 1,14, 2,13, 6,15, 0, 9,10, 4, 5, 3,
 //S6
 12, 1,10,15, 9, 2, 6, 8, 0,13, 3, 4,14, 7, 5,11, 10,15, 4, 2, 7,12, 9, 5, 6, 1,13,14, 0,11, 3, 8, 9,14,15, 5, 2, 8,12, 3, 7, 0, 4,10, 1,13,11, 6, 4, 3, 2,12, 9, 5,15,10,11,14, 1, 7, 6, 0, 8,13,
 //S7
 4,11, 2,14,15, 0, 8,13, 3,12, 9, 7, 5,10, 6, 1, 13, 0,11, 7, 4, 9, 1,10,14, 3, 5,12, 2,15, 8, 6, 1, 4,11,13,12, 3, 7,14,10,15, 6, 8, 0, 5, 9, 2, 6,11,13, 8, 1, 4,10, 7, 9, 5, 0,15,14, 2, 3,12,
 //S8
 13, 2, 8, 4, 6,15,11, 1,10, 9, 3,14, 5, 0,12, 7, 1,15,13, 8,10, 3, 7, 4,12, 5, 6,11, 0,14, 9, 2, 7,11, 4, 1, 9,12,14, 2, 0, 6,10,13,15, 3, 5, 8, 2, 1,14, 7, 4,10, 8,13,15,12, 9, 0, 3, 5, 6,11 };
const int P_Table[32]={ 16, 7,20,21,29,12,28,17, 1,15,23,26, 5,18,31,10, 2, 8,24,14,32,27, 3, 9,19,13,30, 6,22,11, 4,25 };
static bool SubKey[16][48]={0};
char CipherText[33]={'\0'}; //密文也作为全局变量


//非法输入则退出程序
void print_usage() {
	printf("\n非法输入,支持的参数有以下：\n-p plainfile 指定明文文件的位置和名称\n-k keyfile  指定密钥文件的位置和名称\n-v vifile  指定初始化向量文件的位置和名称\n-m mode  指定加密的操作模式(ECB,CBC,CFB,OFB)\n-c cipherfile 指定密文文件的位置和名称。\n");
	exit(-1);
}

//二进制数组拷贝函数
void bit_copy(bool * out_data, bool * in_data,int Num) {
	 int i=0;
 	 for(i=0;i<Num;i++){
	     out_data[i]=in_data[i];
	 }
}

//二进制bool数组转换为16进制字符串,out_data是输出的十六进制字符串，in_data是输入的二进制数组，Num是二进制数的位数
void bit_hex(char *out_data,bool *in_data,int Num)
{
    int i=0;
    for(i=0;i<Num/4;i++)
    {
        out_data[i]=0;
    }
    for(i=0;i<Num/4;i++)
    {
        out_data[i] = (in_data[i*4]<<3)+(in_data[i*4+1]<<2)+(in_data[i*4+2]<<1)+(in_data[i*4+3]<<0);
        if((out_data[i]%16)>9)
        {
            out_data[i]=out_data[i]%16+'7';     //余数大于9时处理 10-15 to A-F
        } //输出字符
        else
        {
            out_data[i]=out_data[i]%16+'0';   //输出字符
        }
    }
}

//十六进制字符串转换为二进制bool数组，out_data是输出的二进制数组，in_data是输入的十六进制字符串，Num是二进制位数
void hex_bit(bool *out_data,char *in_data,int Num)
{
    int i=0;                        // 字符型输入
    for(i=0;i<Num;i++)
    {
        if((in_data[i/4])>'9')         //  大于9
        {
        	//printf("%s", in_data);
            out_data[i]=((in_data[i/4]-'7')>>(3-(i%4)))&0x01;
        }
        else
        {
            out_data[i]=((in_data[i/4]-'0')>>(3-(i%4)))&0x01;
        }
    }
}

//十进制数转二进制数数组函数
void ten_bit(bool * out_data, int in_data, int Num){
	int i;
	for(i=0;i<Num;i++){
		out_data[i]=(in_data>>(3-i))&0x01;
	}
}

//二进制异或函数，message_out与message_in进行异或，得到的结果放在message_out,NUM是二进制数的位数
void Xor(bool * message_out,bool * message_in,int Num){
    int i;
    for(i=0;i<Num;i++){
	   message_out[i]=message_out[i]^message_in[i];
    }
}

//左移位循环函数，out_data是左移位后的二进制数，movstep是左移的位数，len是二进制数的长度
void Loop_bit(bool * out_data,int movstep,int len){
    static bool temp[256]={0};
	bit_copy(temp,out_data,movstep);
	bit_copy(out_data,out_data+movstep,len-movstep);
	bit_copy(out_data+len-movstep,temp,movstep);
}

//置换表函数，out_data是输出的二进制数组，in_data是输入的二进制数组，Table是使用的置换表，Num是二进制数的位数
void TableReplace( bool *out_data, bool * in_data,const int *Table ,int Num){
    int i=0;
 	static bool temp[256]={0};
 	for(i=0;i<Num;i++){
  	    temp[i]=in_data[Table[i]-1];
    }
 	bit_copy(out_data,temp,Num);
}

//子密钥生成函数，Key是初始密钥
void setKey(char Key[16]){
	int i,j;
	static bool Key_bit[64]={0};
	static bool *Key_bit_L, *Key_bit_R;
	Key_bit_L=&Key_bit[0];
	Key_bit_R=&Key_bit[28];
	hex_bit(Key_bit, Key, 64);
	TableReplace(Key_bit, Key_bit, PC1_Table,56);//进行PC-1置换
	for(i=0;i<16;i++){
		Loop_bit(Key_bit_L, Move_Table[i], 28);
		Loop_bit(Key_bit_R, Move_Table[i], 28);
		TableReplace(SubKey[i], Key_bit, PC2_Table,48);
	}
}

//S盒变换函数
void S_change(bool *out_data, bool *in_data){
	bool temp[32]={0};
	char check_Txt[9]={NULL};
	int i;
	int r=0, c=0;
	int check_num=0;
	for(i=0;i<8;i++){
		r=in_data[i*6]*2+in_data[i*6+5];
		c=in_data[i*6+1]*8+in_data[i*6+2]*4+in_data[i*6+3]*2+in_data[i*6+4];
		ten_bit(&temp[i*4], S_Box[i][r][c],4);
	}
	bit_hex(check_Txt, temp, 32);
	bit_copy(out_data,temp,32);
}

//f函数
void f(bool out_data[32],bool in_data[48]){
	char checkText[9]={NULL};
    int i;
    bool check_bit[32]={0};
 	static bool message_E[48]={0};  //存放E置换的结果；
 	TableReplace(message_E,out_data,E_Table,48); //E表置换
 	Xor(message_E,in_data,48);
 	S_change(check_bit,message_E);  //S盒变换
 	bit_copy(out_data, check_bit, 32);
	bit_hex(checkText, out_data, 32);
 	TableReplace(out_data,out_data,P_Table,32);  //P置换
}

//左右分组的交换
void reverse(bool *L,bool *R,int num)
{
	static bool temp[32]={0};
	int i;
	for (i=0;i<num;i++)
	{
		temp[i]=L[i];
		L[i]=R[i];
		R[i]=temp[i];
	}
}

//对于一个数据进行的纯DES加密，给明文16个字符，出密文16个字符
void DES_blockAction(char My_message[16],char HexMssage[16]){
    char checkText[17]={NULL};
	int i;
 	static bool message_bit[64]={0};
 	static bool *message_bit_L=&message_bit[0],*message_bit_R=&message_bit[32];
 	static bool temp[32]={0};
 	hex_bit(message_bit,My_message,64);
 	TableReplace(message_bit,message_bit,IP_Table,64);
 	bit_hex(checkText, message_bit, 64);
 	for(i=0;i<16;i++){
  	    bit_copy(temp,message_bit_R,32);
  		f(message_bit_R,SubKey[i]); //对Ri-1进行f变换
  		Xor(message_bit_R,message_bit_L,32);//Ri-1和Li-1异或得到Ri
  		bit_copy(message_bit_L,temp,32);
    }
    reverse(message_bit_L, message_bit_R, 32);
 	TableReplace(message_bit,message_bit,IPR_Table,64);
 	bit_hex(HexMssage,message_bit,64);  //二进制转换成十六进制
}

//ECB模式
void ECB(char *My_message, int count, char *toFile){
    int k=0;
    char CipherText[17]={'\0'};
    FILE *fp=fopen(toFile, "a");
    for(int i=0; i<count; ++i){
        char PlainText[17]={'\0'};
        for(int j=0; j<16; ++j){
            PlainText[j] = My_message[k++]; //一组一组地提取明文做转换
        }
        DES_blockAction(PlainText, CipherText);
        printf("%s",CipherText);
        fprintf(fp, "%s", CipherText);
    }
    fclose(fp);
}

//CBC模式
void CBC(char *My_message, char *Vi_message, int count, char *toFile){
    static bool Vi_bit[64]={0};
    bool cipher_bit[64]={0};  //每次Ek之后的值
    hex_bit(Vi_bit,Vi_message,64); //初始化向量转bit
    int k=0;
    FILE *fp2=fopen(toFile, "a");
    for(int m=1; m<=count; ++m){ //开始分块
        char messageBlock[17]={'\0'};
        for(int i=0;i<16;++i){
            messageBlock[i] = My_message[k++];
        }  //提出每次的明文字符分组
        bool messageBlock_bit[64]={0}; //对于每一明文分组的bit数组都可初始化一次
        hex_bit(messageBlock_bit,messageBlock,64); //明文分组转bit，准备异或
        if(m==1){
            Xor(messageBlock_bit, Vi_bit, 64);  //第一个明文分组和初始化向量异或
        }
        else{
            Xor(messageBlock_bit, cipher_bit, 64);
        }
        char cipher[17]={'\0'};
        bit_hex(messageBlock, messageBlock_bit, 64); //转成字符型了进行加密
        DES_blockAction(messageBlock,cipher); //cipher是字符串，cipher_bit是bool数组
        printf("%s",cipher); //出来一个数据块的密文就打印
        fprintf(fp2, "%s", cipher);
        hex_bit(cipher_bit,cipher,64);
    }
    fclose(fp2);
}

//CFB模式
void CFB(char *My_message, char *Vi_message, int count, char *toFile){
    count *=8; //CFB形式的分组小得多
    char cipherBlock[17] = {'\0'}; //密文分组
    char afterEncryp[17]={'\0'};
    bool cipherBlock_bit[64]={0};  //用作移位寄存器，初始时是初始向量的64bit
    hex_bit(cipherBlock_bit,Vi_message,64);
    int k=0;

    FILE *fp3=fopen(toFile, "a");
    for(int m=1; m<=count; ++m){
        if(m==1){
            DES_blockAction(Vi_message,afterEncryp);
        }
        else{
            DES_blockAction(cipherBlock,afterEncryp);
        }
        bool afterEncryp_bit[8] = {0}; //准备选加密后64bit的前8bit
        char afterEncryp_keep[3] = {'\0'};
        afterEncryp_keep[0] = afterEncryp[0];
        afterEncryp_keep[1] = afterEncryp[1]; //保留前8bit
        hex_bit(afterEncryp_bit,afterEncryp_keep,8);

        char messageBlock[3]={'\0'};
        for(int i=0;i<2;++i){
            messageBlock[i] = My_message[k++];
        }  //提出每次的明文字符分组
        bool messageBlock_bit[8]={0};  //对于每一明文分组的bit数组都可初始化一次
        hex_bit(messageBlock_bit,messageBlock,8); //明文分组转bit，准备异或

        Xor(messageBlock_bit, afterEncryp_bit, 8);
        bit_hex(messageBlock,messageBlock_bit,8);
        printf("%s", messageBlock);  //8bit-输出两个字符
        fprintf(fp3, "%s", messageBlock);

        Loop_bit(cipherBlock_bit,8,64);
        for(int n=56,p=0; n<64; ++n){
            cipherBlock_bit[n]=messageBlock_bit[p++];
        }  //完成左移并替换最右8bit
        bit_hex(cipherBlock,cipherBlock_bit,64);
    }
    fclose(fp3);
}

//OFB模式
void OFB(char *My_message, char *Vi_message, int count, char *toFile){
    count *=8; //CFB形式的分组小得多
    char cipherBlock[17] = {'\0'}; //密文分组
    char afterEncryp[17]={'\0'};
    bool vi_bit[64]={0};  //用作移位寄存器，初始时是初始向量的64bit，一直在变
    hex_bit(vi_bit,Vi_message,64);
    int k=0;

    FILE *fp4=fopen(toFile, "a");
    for(int m=1; m<=count; ++m){
        if(m==1){
            DES_blockAction(Vi_message,afterEncryp);
        }
        else{
            DES_blockAction(cipherBlock,afterEncryp);
        }
        bool afterEncryp_bit[8] = {0}; //准备选加密后64bit的前8bit
        char afterEncryp_keep[3] = {'\0'};
        afterEncryp_keep[0] = afterEncryp[0];
        afterEncryp_keep[1] = afterEncryp[1]; //保留前8bit
        hex_bit(afterEncryp_bit,afterEncryp_keep,8);

        char messageBlock[3]={'\0'};
        for(int i=0;i<2;++i){
            messageBlock[i] = My_message[k++];
        }  //提出每次的明文字符分组
        bool messageBlock_bit[8]={0};  //对于每一明文分组的bit数组都可初始化一次
        hex_bit(messageBlock_bit,messageBlock,8); //明文分组转bit，准备和加密后的左边8bit异或

        Xor(messageBlock_bit, afterEncryp_bit, 8);
        bit_hex(messageBlock,messageBlock_bit,8);
        printf("%s", messageBlock);  //8bit-输出两个字符
        fprintf(fp4, "%s", messageBlock);

        Loop_bit(vi_bit,8,64);
        for(int n=56,p=0; n<64; ++n){
            vi_bit[n]=afterEncryp_bit[p++];
        }  //完成左移并替换最右8bit
        bit_hex(cipherBlock,vi_bit,64);
    }
    fclose(fp4);
}

//主函数，程序执行的入口
int main(int argc, char** argv) {
    char* plainfile = NULL;
    char* keyfile = NULL;
    char* vifile = NULL;
    char* mode = NULL;
    char* cipherfile = NULL; //输入的各文件路径字符串,char*指向的内容存放在常量区，不能改变

    //确认输入无误，对应找到文件名
	if (argc % 2 == 0) {
		print_usage();  //一print_usage就会exit(-1)
	}
    for (int i=1; i < argc; i += 2) {
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
		case 'm':  //char *mode
			if (strcmp(argv[i + 1], DES_MODE[0]) != 0 && strcmp(argv[i + 1], DES_MODE[1]) != 0 && strcmp(argv[i + 1], DES_MODE[2]) != 0 && strcmp(argv[i + 1], DES_MODE[3]) != 0) {
				print_usage(); //输入的不是给定的四种模式
			}
			mode = argv[i + 1];
			break;
		case 'c':
			cipherfile = argv[i + 1];
			break;
		default:
			print_usage(); //输入了奇怪参数
		}
	}
	if (plainfile == NULL || keyfile == NULL || mode == NULL || cipherfile == NULL) {
		print_usage(); //一定要指明的
	}
	if (strcmp(mode, "ECB") != 0 && vifile == NULL) {
		print_usage(); //除了ECB模式，其他都一定要给vifile
	}

    char PlainText[33]={'\0'};
	char KeyText[17]={'\0'};
	char ViText[17]={'\0'};
	//密文已经作为全局变量了，不在此设置
    int blockCount=2; //给定的测试数据是两个分组即可

	FILE *fp = fopen(plainfile, "r");
    fread(PlainText, 33, 1, fp);
    fclose(fp);

	FILE *fp2 = fopen(keyfile, "r");
    fread(KeyText, 17, 1, fp);
    fclose(fp2);
	setKey(KeyText);

	if (strcmp(mode, "ECB") != 0) {
		FILE *fp3 = fopen(vifile, "r");
        fread(ViText, 17, 1, fp);
        fclose(fp3);
	}

	//根据给定的模式进行加密
    if (strcmp(mode, "ECB") == 0) {
		ECB(PlainText, blockCount, cipherfile);
	}
	else if (strcmp(mode, "CBC") == 0) {
		CBC(PlainText, ViText, blockCount, cipherfile);
	}
	else if (strcmp(mode, "CFB") == 0) {
		CFB(PlainText, ViText, blockCount, cipherfile);
	}
	else if (strcmp(mode, "OFB") == 0) {
		OFB(PlainText, ViText, blockCount, cipherfile);
	}
	else {
		//不应该能到达这里
		printf("致命错误！！！\n");
		exit(-2);
	}
    printf("\n%s\n", "Already written to the file.");
	return 0;
}
