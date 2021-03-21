#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#define Nb 4//Number of block(Nb = 4) (4 * block size = 128), blocksize=4(區塊) * 8(每區塊8bit) =32
int Nr = 0;//加密及解密編解碼的運算回合次數，分別是AES-128(10r), AES-192(12), AES-256(14)。
int Nk = 0;//鑰匙(每block-32bits)的block數量 AES-128(4 block), AES-192(6), AES-256(8) 
unsigned char input[16];       // plaintext block input array, 明文區塊輸入char陣列
unsigned char output[16];      // ciphertext block output array, 密文區塊輸出陣列
unsigned char state[4][4];     // temp state array in encrypt state, 加密運算過程中的的狀態陣列 4 * 4 
unsigned char Roundkey[240];   // AES-128 -> 44 * 4 = 176, AES-256 -> 60 * 4  = 240
/*
round key array, stored Main Key and Expanded Key 
(Ex: AES-128(44words/176 bytes),AES-192(52w/208bytes), AES-256(60w/240bytes)), 
儲存主要鑰匙跟擴充鑰匙的陣列, w0(index 0 ~ 3) w1(index 4 ~ 7)....
*/
unsigned char Key[32];         // Main key(input key Ex. AES-128(16 char), AES-256(32 char)), 輸入的金鑰
//only use for 3-AES *****
unsigned char Key1[32];//*         
unsigned char Key2[32];//*
//************************
typedef unsigned char byte;
unsigned int compress_col[4];  //加速版壓縮column --> 32bits = 4 * 8 bits 
int tMix_inv_flag = 1;// 紀錄是否做過expansionKey的mixcolumn_inv() ， 1 -> 還沒做 ，0 -> 做過 
// xtime macro: (x*{02}) mod {1b} 
#define xtime(x)   ((x<<1) ^ (((x>>7) & 0x01) * 0x1b))

// Multiplty macro: (x * y) mod GF(2^8)
#define Multiply(x,y) (((y & 1) * x) ^ ((y>>1 & 1) * xtime(x))\
                      ^ ((y>>2 & 1) * xtime(xtime(x)))\
                      ^ ((y>>3 & 1) * xtime(xtime(xtime(x))))\
                      ^ ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))
/*
AES 演算法共有 3 個重要的參數: 
1.加解密區塊數目(Nb) :(number of block)被加解密的data，以 32bits (1 word)為一區塊單位。
2.金鑰區塊數目(Nk) ：(number of block of key)金鑰長度，以 32bits (1 word)為一區塊單位。
3.運算回合次數(Nr)：(number of round)加密及解密編解碼的運算回合次數。 
Nr=6+Nk
*/ 
void AES_encrypt(); 	 //AES加密主程式 
void AES_decrypt(); 	 //AES解密主程式 
void SubBytes();		 //加密subbytes 
void SubBytes_inv();	 //解密sunbyte 
void ShiftRows();		 //加密shiftrow 
void ShiftRows_inv();	 //解密shiftrow 
void Mixcolumn();		 //加密Mixcolumn 
void Mixcolumn_inv();	 //解密Mixcolumn 
void addroundkey(int round);//加密解密addroundkkey 
int getSBOX(int num);	 //加密用s_box 
int getSBOX_inv(int num);//解密用s_box 
void keyExpansion(unsigned char Key[]);
//加密工作模式 
void ECB_AES_encrypt(int file_len, char* p, char* out, int padding_len, int table_mode); 
void ECB_AES_decrypt(int file_len, char* p, char* out,  int table_mode);
void CFB_8_encrypt(int file_len, int Iv[], char* p, char* out, int table_mode);
void CFB_8_decrypt(int file_len, int Iv[], char* p, char* out, int table_mode);
void OFB_8_encrypt(int file_len, int Iv[], char* p, char* out, int table_mode);//OFB加解密共用 
void CTR_8_encrypt(int file_len, int counter[], char* p, char* out, int padding_len, int table_mode);
void CBC_AES_encrypt(int file_len, int Iv[], char* p, char* out, int padding_len, int table_mode);
void CBC_AES_decrypt(int file_len, int Iv[], char* p, char* out, int table_mode);
//矩陣模仿10進位 
void counter_plus(int counter[]);
//3-AES 
void triple_AES_encrypt(int file_len, char* p, char* out, int table_mode, int padding_len);
void triple_AES_decrypt(int file_len, char* p, char* out, int table_mode, int KeySize0);
//查表加速版
void AES_tbox_encrypt();
void AES_tbox_decrypt();
int getTe0(int);
int getTe1(int);
int getTe2(int);
int getTe3(int);
int getDe0(int);
int getDe1(int);
int getDe2(int);
int getDe3(int);
/*
rcon(i)=b^{i-1}{mod {x}}^{8}+x^{4}+x^{3}+x+1} 
為求2的冪次 
*/ 
int counter[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};//計數器 - CTR mode
int Iv[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};//初始化向量 
int Rcon[10] = {
//      1     2     3      4    5     6     7     8    9     10
     0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

int main(){
	FILE *fin, *fout, *fout2; // input file pointer, output file pointer
    int KeySize = 0; // key Size:128、192、256 
    unsigned char norce[8];
    unsigned char decryIv[16];
    unsigned char input_key[32]; // user input AES Main Key (limit:256bit)
    unsigned char plaintext_block[16]; // plaintext, encrpty each block (128bit) once
    char fileName[50];//the variable which will be input or output   
	int flen;//檔案長度 
	int mode;//選擇加密工作模式 
	char *p ;//檔案輸入指標 
	char *out ;//檔案輸出指標
	int padding_len = 0;
	int table_mode = 0;//是否使用查表加速模式 
	srand(time(NULL));//用時間取隨機數字 
	
    /*輸入檔案名字*/ 
    printf("Enter file name to encrypt plaintext \n(ex. gg.txt , gg.txt要先建立)=> ");
    scanf("%s", fileName);

    if ((fin = fopen(fileName, "r+b")) == NULL){
        printf("Open file Erorr...\n");
        return(0);
    }
    
    fseek(fin, 0, SEEK_END); /* 定位到檔案末尾 */
	flen = ftell(fin); /* 得到檔案大小 */
    p = (char *)calloc(flen, sizeof(char)); /* 根據檔案大小動態分配記憶體空間 */
	if(p==NULL){
		fclose(fin);
		printf("open file error ...\n");
		return 0;
	}
	
	fseek(fin, 0, SEEK_SET); /* 定位到檔案開頭 */
	fread(p, flen, 1, fin);  /* 一次性讀取全部printf("\n");檔案內容 */
	printf("輸入檔案內容 : \n%s\n", p);
	printf("輸入檔案長度 : %d\n", flen);
    /* 輸出檔案名自 */
    printf("Enter file name to store decrypted plaintext \n(ex. ss.txt, ss.txt可不用存在)  => "); 
    scanf("%s", fileName); 
	fout = fopen(fileName,"w+b"); 
    
	//輸入key的部分 
	while (KeySize != 128 && KeySize != 192 && KeySize != 256){
        printf("Enter AES key size (Only 128 or 192 or 256) : ");
        scanf("%d", &KeySize);
    }
	
    Nk = KeySize / 32; // Number of block of key, 計算key block數量 (Ex: AES-128 : 4) 
    Nr = Nk + 6;       // Number of round(Nr),  計算AES 運算回合次數 (Ex:AES-128 : 10)
	
    if(KeySize == 128) {
       	printf("請輸入秘密鑰匙(16個字元) =>");
		scanf("%16s", input_key);
//		fread(input_key, char, 17, stdin);
		//清空緩衝區 
		scanf("%*[^\n]");
		scanf("%*c");
        for(int i = 0; i < 16; i++)
           Key[i] = input_key[i];
    }
    else if(KeySize == 192) { 
        printf("請輸入秘密鑰匙(24個字元) =>");
		scanf("%16s", input_key);	
		//清空緩衝區 
		scanf("%*[^\n]");
		scanf("%*c");
        for(int i = 0; i < 24; i++)
           Key[i] = input_key[i];
    }
    else if(KeySize == 256){
        printf("請輸入秘密鑰匙(32 個字元) =>");
		scanf("%16s", input_key);
		//清空緩衝區 
		scanf("%*[^\n]");
		scanf("%*c");
        for(int i = 0; i < 32; i++)
           Key[i] = input_key[i];
    }else{
    	printf("輸入有誤，即將離開...");
    	return 0;
	}
	keyExpansion(Key);//金鑰擴展 
	
	//是否使用查表法 
	printf("是否要使用查表加密法\n輸入0-->不使用\n輸入1-->使用\n你的輸入: ");
	scanf("%1d", &table_mode);
	//清空緩衝區 
	scanf("%*[^\n]");
	scanf("%*c");
	printf("正在使用模式: %d\n", table_mode);
	
	printf("請選擇模式\n" 
			"1. CFB-8 加密模式\n" 			
			"2. CFB-8 解密模式\n"
			"3. OFB-8 加密模式\n"
			"4. OFB-8 解密模式\n"
			"5. CTR   加密模式\n"
			"6. CTR   解密模式\n"
			"7. ECB   加密模式\n"
			"8. ECB   解密模式\n"
			"9. CBC   加密模式\n"
		    "10.CBC   解密模式\n"
		    "11.3-AES 加密模式\n"
		    "12.3-AES 解密模式\n"
			"選擇模式 : "
			);
	scanf("%d", &mode);
	switch(mode){
		case 1://CFB
			fout2 = fopen("Iv.txt","w+b"); //output Iv
			printf("此次加密初始化向量為 :"); 
			for(int i = 0;i < 16;i++){
				int ran = rand() % 10;
				Iv[i] = ran;
				printf("%d", Iv[i]);
				fprintf(fout2, "%d", Iv[i]);
			}
			printf("\n");
			out = (char *)calloc(flen, sizeof(char) );
			CFB_8_encrypt(flen, Iv, p, out, table_mode);
			break;
		case 2:
			printf("請輸入加密時所得到的初始化向量 :");
			scanf("%s", decryIv);
			for(int i = 0; i < 16; i++){
				Iv[i] = decryIv[i] - '0';// 減掉ACSII 0 = 48 
			}
			printf("\n");
			out = (char *)calloc(flen, sizeof(char));
			CFB_8_decrypt(flen, Iv, p, out, table_mode);
			break;
		case 3://OFB
			fout2 = fopen("Iv.txt","w+b");//output Iv
			printf("此次加密初始化向量為 :"); 
			for(int i = 0; i < 16; i++){
				int ran = rand() % 10;
				Iv[i] = ran;
				printf("%d", Iv[i]);
				fprintf(fout2, "%d", Iv[i]);
			}
			printf("\n");
			out = (char *)calloc(flen, sizeof(char) );
			OFB_8_encrypt(flen, Iv, p, out, table_mode);
			break;
		case 4:
			printf("請輸入加密時所得到的初始化向量 :");
			scanf("%s", decryIv);
			for(int i = 0; i < 16; i++){
				Iv[i] = decryIv[i] - '0';// 減掉ACSII 0 = 48 
			}
			printf("\n");
			out = (char *)calloc(flen, sizeof(char) );
			OFB_8_encrypt(flen, Iv, p, out, table_mode);
			break;
		case 5://CTR
			fout2 = fopen("norce.txt","w+b"); //output counter
			if( (flen % 16) != 0){
				padding_len = 16 - (flen % 16); //需要padding數 
				flen = flen + padding_len;
			}
			printf("norce:");
			for(int i = 0; i < 8; i++){
				int ran = rand() % 10;
				counter[i] = ran;
				printf("%d", counter[i]);
				fprintf(fout2, "%d", counter[i]);
			}
			printf("\n");
			out = (char *)calloc(flen, sizeof(char) );
			CTR_8_encrypt(flen, counter, p, out, padding_len, table_mode);
			break;
		case 6:
			printf("請輸入加密時所得到的隨機數(norce) :");
			scanf("%s", norce);
			for(int i = 0; i < 8; i++){
				counter[i] = norce[i] - '0';// 減掉ACSII 0 = 48 
				printf("%d", counter[i]);
			}
			out = (char *)calloc(flen, sizeof(char) );
			CTR_8_encrypt(flen, counter, p, out, padding_len, table_mode);
			break;
		case 7://ECB
			if( (flen % 16) != 0){
				padding_len = 16 - (flen % 16); //需要padding數 
				flen = flen + padding_len;
			}
			out = (char *)calloc(flen, sizeof(char) );
			ECB_AES_encrypt(flen, p, out, padding_len, table_mode);
			break;
		case 8:
			out = (char *)calloc(flen, sizeof(char) );
			ECB_AES_decrypt(flen, p, out, table_mode);
			break;
		case 9://CBC
			if( (flen % 16) != 0){
				padding_len = 16 - (flen % 16); //需要padding數 
				flen = flen + padding_len;
			}
			fout2 = fopen("Iv.txt", "w+b"); //output Iv
			printf("此次加密初始化向量為 :"); 
			for(int i = 0;i < 16;i++){
				int ran = rand() % 10;
				Iv[i] = ran;
				printf("%d", Iv[i]);
				fprintf(fout2, "%d", Iv[i]);
			}
			printf("\n");
			out = (char *)calloc(flen+1, sizeof(char) );
			CBC_AES_encrypt(flen, Iv, p, out, padding_len, table_mode);
			flen = flen+1;
			break;
		case 10:
			printf("請輸入加密時所得到的初始化向量 :");
			scanf("%s", decryIv);
			for(int i = 0;i < 16; i++){
				Iv[i] = decryIv[i] - '0';// 減掉ACSII 0 = 48 
			}
			printf("\n");
			out = (char *)calloc(flen-1, sizeof(char) );////////flen
			CBC_AES_decrypt(flen-1, Iv, p, out, table_mode);
			flen = flen - 1;	
			break;
		case 11:
			int padding_len;
			if( (flen % 16) != 0){
				padding_len = 16 - (flen % 16); //需要padding數 
				flen = flen + padding_len;
			}else{
				padding_len = 0;
			}
			
			out = (char *)calloc(flen, sizeof(char) );
			triple_AES_encrypt(flen, p, out, table_mode, padding_len);
			break;
		case 12:
			out = (char *)calloc(flen, sizeof(char) );
			triple_AES_decrypt(flen, p, out, table_mode, KeySize);//將第一次輸入的 密鑰size傳入 
			break;
	}

	printf("輸出檔案長度 : %d \n", flen);
	printf("輸出檔案內容 :\n%s\n", out);
	
	for (int i = 0; i < flen; i++){
		fprintf(fout, "%c", out[i]);
//		printf("i->%d: %x\n", i, out[i]);
	} 

    fclose(fin);
    fclose(fout);
    fclose(fout2);
    free(out);
	free(p);

	return 0;
}
//加密工作模式 
void triple_AES_encrypt(int file_len, char* p, char* out, int table_mode, int padding_len){
	
	int KeySize1, KeySize2 = 0;//第二把加密鑰匙 
	unsigned char input_key[32];
	char *reg = (char *)calloc(file_len, sizeof(char));//存output給下一次加密當input 

//	第一把key加密 
	ECB_AES_encrypt(file_len, p, out, padding_len, table_mode);
	//輸出存在out指標
	//將out指標的值傳入reg當作下一次的輸入 
	for(int i = 0;i < file_len; i++){
		reg[i] = out[i];
	}
	
//	第二把key 
	while (	KeySize1 != 128 && KeySize1 != 192 && KeySize1 != 256){
        printf("輸入第二把鑰匙 (Only 128 or 192 or 256) : ");
        scanf("%d", &KeySize1);
    }
    if(KeySize1 == 128) {
        printf("請輸入秘密鑰匙(16個字元) =>");
		scanf("%16s", input_key);
		//清空緩衝區 
		scanf("%*[^\n]");
		scanf("%*c");
        for(int i=0; i<16; i++)
           Key1[i] = input_key[i];
    }
    else if(KeySize1 == 192) { 
        printf("請輸入秘密鑰匙(24個字元) =>");
		scanf("%24s", input_key);	
		//清空緩衝區 
		scanf("%*[^\n]");
		scanf("%*c");
        for(int i=0; i<24; i++)
           Key1[i] = input_key[i];
    }
    else if(KeySize1 == 256){
        printf("請輸入秘密鑰匙(32 個字元) =>");
		scanf("%32s", input_key);
		//清空緩衝區 
		scanf("%*[^\n]");
		scanf("%*c");
        for(int i=0; i<32; i++)
           Key1[i] = input_key[i];
    }
	
	Nk = KeySize1 / 32; // Number of block of key, 計算key block數量 (Ex: AES-128 : 4) 
    Nr = Nk + 6;       // Number of round(Nr),  計算AES 運算回合次數 (Ex:AES-128 : 10)
	keyExpansion(Key1); //第二把金鑰擴展 
	//把二把key解密 
	ECB_AES_decrypt(file_len, reg, out, table_mode);
	//將out傳到reg讓第三把key加密 
	for(int i = 0;i < file_len; i++){
		reg[i] = out[i];
	}
	
	//第三把key
	while (KeySize2 != 128 && KeySize2 != 192 && KeySize2 != 256){
        printf("輸入第三把鑰匙 (Only 128 or 192 or 256) : ");
        scanf("%d", &KeySize2);
    }
    if(KeySize2 == 128) {
       	printf("請輸入秘密鑰匙(16個字元) =>");
		scanf("%16s", input_key);
		//清空緩衝區 
		scanf("%*[^\n]");
		scanf("%*c");
        for(int i = 0; i < 16; i++)
           Key2[i] = input_key[i];
    }
    else if(KeySize2 == 192) { 
       	printf("請輸入秘密鑰匙(24個字元) =>");
		scanf("%24s", input_key);	
		//清空緩衝區 
		scanf("%*[^\n]");
		scanf("%*c");
       	for(int i = 0; i < 24; i++)
           Key2[i] = input_key[i];
    }
    else if(KeySize2 == 256){
       	printf("請輸入秘密鑰匙(32 個字元) =>");
		scanf("%32s", input_key);
		//清空緩衝區 
		scanf("%*[^\n]");
		scanf("%*c");
       	for(int i = 0; i < 32; i++)
           Key2[i] = input_key[i];
    }
    
    Nk = KeySize2 / 32; // Number of block of key, 計算key block數量 (Ex: AES-128 : 4) 
    Nr = Nk + 6;        // Number of round(Nr),  計算AES 運算回合次數 (Ex:AES-128 : 10)
    keyExpansion(Key2);
    ECB_AES_encrypt(file_len, reg, out, 0, table_mode);//padding_len設為0 
	
}
void triple_AES_decrypt(int file_len, char* p, char* out, int table_mode, int KeySize0){
	
	int KeySize1, KeySize2;
	unsigned char input_key[32];
	char *reg = (char *)calloc(file_len, sizeof(char));//存output給下一次加密當input 
	
//	第二把key 
	while (	KeySize1 != 128 && KeySize1 != 192 && KeySize1 != 256){
        printf("輸入第二把鑰匙 (Only 128 or 192 or 256) : ");
        scanf("%d", &KeySize1);
    }
    if(KeySize1 == 128) {
        printf("請輸入秘密鑰匙(16個字元) =>");
		scanf("%16s", input_key);
		//清空緩衝區 
		scanf("%*[^\n]");
		scanf("%*c");
        for(int i = 0; i < 16; i++)
           Key1[i] = input_key[i];
    }
    else if(KeySize1 == 192) { 
        printf("請輸入秘密鑰匙(24個字元) =>");
		scanf("%24s", input_key);	
		//清空緩衝區 
		scanf("%*[^\n]");
		scanf("%*c");
        for(int i = 0; i < 24; i++)
           Key1[i] = input_key[i];
    }
    else if(KeySize1 == 256){
       printf("請輸入秘密鑰匙(32 個字元) =>");
       scanf("%32s", input_key);
		//清空緩衝區 
		scanf("%*[^\n]");
		scanf("%*c");
        for(int i = 0; i < 32; i++)
           Key1[i] = input_key[i];
    }
    
	//第三把key
	while (KeySize2 != 128 && KeySize2 != 192 && KeySize2 != 256){
        printf("輸入第三把鑰匙 (Only 128 or 192 or 256) : ");
        scanf("%d", &KeySize2);
    }
    if(KeySize2 == 128) {
        printf("請輸入秘密鑰匙(16個字元) =>");
		scanf("%16s", input_key);
		//清空緩衝區 
		scanf("%*[^\n]");
		scanf("%*c");
        for(int i=0; i<16; i++)
           Key2[i] = input_key[i];
    }
    else if(KeySize2 == 192) { 
        printf("請輸入秘密鑰匙(24個字元) =>");
		scanf("%24s", input_key);	
		//清空緩衝區 
		scanf("%*[^\n]");
		scanf("%*c");
        for(int i=0; i<24; i++)
           Key2[i] = input_key[i];
    }
    else if(KeySize2 == 256){
        printf("請輸入秘密鑰匙(32 個字元) =>");
		scanf("%32s", input_key);
		//清空緩衝區 
		scanf("%*[^\n]");
		scanf("%*c");
        for(int i=0; i<32; i++)
           Key2[i] = input_key[i];
    }
    
    Nk = KeySize2 / 32; // Number of block of key, 計算key block數量 (Ex: AES-128 : 4) 
    Nr = Nk + 6;       // Number of round(Nr),  計算AES 運算回合次數 (Ex:AES-128 : 10)
    keyExpansion(Key2);
    ECB_AES_decrypt(file_len, p, out, table_mode);//padding_len設為0 
    //存入reg 
    for(int i = 0;i < file_len; i++){
		reg[i] = out[i];
	}
	tMix_inv_flag = 1;  //設為1。需要mix_inv() 
    
    Nk = KeySize1 / 32; // Number of block of key, 計算key block數量 (Ex: AES-128 : 4) 
    Nr = Nk + 6;       // Number of round(Nr),  計算AES 運算回合次數 (Ex:AES-128 : 10)
	keyExpansion(Key1); //第二把金鑰擴展 
	//存入reg 
	ECB_AES_encrypt(file_len, reg, out, 0, table_mode);
	for(int i = 0;i < file_len; i++){
		reg[i] = out[i];
	}
	tMix_inv_flag = 1; //設為1。需要mix_inv() 
		
	Nk = KeySize0 / 32; // Number of block of key, 計算key block數量 (Ex: AES-128 : 4) 
    Nr = Nk + 6;       // Number of round(Nr),  計算AES 運算回合次數 (Ex:AES-128 : 10)
	keyExpansion(Key); //第一把金鑰擴展 
	ECB_AES_decrypt(file_len, reg, out, table_mode);
	
}
void ECB_AES_encrypt(int file_len, char *p, char* out, int padding_len, int table_mode){

	char *reg = (char *)calloc( file_len, sizeof(char));
	for(int i = 0;i < (file_len - padding_len); i++){
		reg[i] = p[i];
	}
	for(int i = file_len - 1; i >= (file_len - padding_len); i--){
		reg[i] = 0;
	}
	
    int round = 0;
    while(file_len > 0){

        for (int c = 0;c < 16;c++){
            input[c] = reg[round * 16 + c];
        }
        
        if(table_mode == 0)
        	AES_encrypt(); 
		else 
			AES_tbox_encrypt(); 
        
        for(int i = 0; i < 16; i++){
            out[round * 16 + i] = output[i] ;
        }
        
        round++;//next round
        file_len = file_len - 16;//每16位使用一次加密器 
    }
} 
void ECB_AES_decrypt(int file_len, char *p, char* out, int table_mode){

    int round = 0;
    while(file_len > 0){

        for (int c = 0;c < 16;c++){
            input[c] = p[round * 16 + c];
        }
        
        if(table_mode == 0)
        	AES_decrypt(); 
		else 
			AES_tbox_decrypt();
			
        for(int i = 0; i < 16; i++){
            out[round * 16 + i] = output[i] ;
        }
        
        round++;//next round
        file_len = file_len - 16;//每16位使用一次加密器 
    }
}
void CBC_AES_encrypt(int file_len, int Iv[], char* p, char* out, int padding_len, int table_mode){

	char *reg = (char *)calloc( file_len, sizeof(char));

	for(int i = 0;i < (file_len - padding_len); i++)
		reg[i] = p[i];
	for(int i = file_len - 1; i >= (file_len - padding_len); i--)
		reg[i] = 0;
		
	int round = 0;
    while(file_len>0){
        for (int c = 0;c < 16;c++){
            input[c] = reg[round * 16 + c] ^ Iv[c];
        }
        if(table_mode==0)
        	AES_encrypt(); 
		else 
			AES_tbox_encrypt(); 
			
        for(int i = 0; i < 16; i++){
            out[round * 16 + i + 1] = output[i];
        	Iv[i] = output[i];
		}
        round++;//next round
        file_len = file_len - 16;//每128位使用一次加密器 
    }
    out[0] = padding_len;
    
    free(reg);
}
void CBC_AES_decrypt(int file_len, int Iv[], char* p, char* out, int table_mode){

    int round = 0;
    
    while(file_len>0){
        for (int c = 0;c < 16;c++){
            input[c] = p[round * 16 + c + 1];
            if(round>=1)
            	Iv[c] = p[(round-1) * 16 + c + 1];
        }
        
        if(table_mode==0)
        	AES_decrypt(); 
		else 
			AES_tbox_decrypt(); 
			
		for(int i = 0; i < 16; i++){
		    out[round * 16 + i] = output[i] ^ Iv[i];
		}
        round++;//next round
        file_len = file_len - 16;//每128位使用一次加密器 
    }
}
/*
CFB-8的加密流程
1. 使用加密器加密IV的資料；
2. 將明文的最高8位與IV的最高8位異或得到8位密文；
3. 將IV資料左移8位，最低8位用剛剛計算得到的8位密文補上。
重複1到3
*/
void CFB_8_encrypt(int file_len, int Iv[], char *p, char* out, int table_mode){

	int round = 0;//判斷第幾個block	

	while(file_len > 0){
		//加密Iv 
		for (int c = 0;c < 16;c++){
            input[c] = Iv[c];
        }
        
		if(table_mode == 0)
        	AES_encrypt(); 
		else 
			AES_tbox_encrypt(); 
		
		//將明文的最高8位與IV的最高8位異或得到8位密文；
		//以Iv做為暫存器 
		for(int i = 0; i < 1; i++){
			out[round * 1 + i] = p[round * 1 + i] ^ output[i];
			//將IV資料左移8位，最低8位用剛剛計算得到的8位密文補上
			Iv[i] = Iv[i + 1];// 左移8位
			Iv[i + 1] = out[round * 1 + i];//儲存計算得到的8位密文
		}
		
		round++;//next round
		file_len = file_len - 1;//每8位使用一次加密器 
	}

}
void CFB_8_decrypt(int file_len, int Iv[], char *p, char* out, int table_mode){

	int round = 0;//判斷第幾個block	
	while(file_len > 0){
		//加密Iv 
		for (int c = 0;c < 16;c++){
            input[c] = Iv[c];
        }
        //結果存在output 
		if(table_mode == 0)
        	AES_encrypt(); 
		else 
			AES_tbox_encrypt(); 
		
		//將明文的最高8位與IV的最高8位異或得到8位密文；
		for(int i = 0; i < 1; i++){
			out[round * 1 + i] = p[round * 1 + i] ^ output[i];
			Iv[i] = Iv[i + 1] ;
			Iv[i + 1] = p[round * 1 + i];//將密文當作新的Iv輸入 
		}
		
		round++;//next round
		file_len = file_len - 1;//每8位使用一次加密器 
	}
}
//由於XOR操作的對稱性，OFB加密和解密操作是完全相同的
void CTR_8_encrypt(int file_len, int counter[], char *p, char* out, int padding_len, int table_mode){
	char *reg = (char *)calloc( file_len, sizeof(char));
	
	for(int i = 0;i < (file_len - padding_len); i++){
		reg[i] = p[i];
	}
	//zero - padding
	for(int i = file_len - 1; i >= (file_len - padding_len); i--){
		reg[i] = 0;
	}
	
	int round = 0;//判斷第幾個block	

	while(file_len > 0){
		//加密Counter 
		for (int c = 0; c < 16;c++){
            input[c] = counter[c];
        }
        
		if(table_mode == 0)
        	AES_encrypt(); 
		else 
			AES_tbox_encrypt(); 
		
		//將明文的最高8位與counter的最高8位異或得到8位密文；
		for(int i = 0; i < 16; i++){
			out[round * 16 + i] = reg[round * 16 + i] ^ output[i];
		}	
		
		round++;//next round
		counter_plus(counter); 
		
		file_len = file_len - 16;//每128位使用一次加密器 
	}
	
	free(reg);
}
void OFB_8_encrypt(int file_len, int Iv[], char *p, char* out, int table_mode){
	
	int round = 0;//判斷第幾個block	

	while(file_len > 0){
		//加密Iv 
		for (int c = 0;c < 16;c++){
            input[c] = Iv[c];
        }
        
		if(table_mode == 0)
        	AES_encrypt(); 
		else 
			AES_tbox_encrypt();
			
		//將明文的最高8位與IV的最高8位異或得到8位密文；
		for(int i = 0; i < 1; i++){
			out[round * 1 + i] = p[round * 1 + i] ^ output[i];
		}
		//以Iv做為暫存器 
		for (int i = 0; i < 16; i++){
			//將加密後的Iv(在output中，存進Iv) 
			Iv[i] =  output[i];
		}		
		
		round++;//next round
		file_len = file_len - 1;//每8位使用一次加密器 
	}
}
//counter矩陣模仿十進位加法 
void counter_plus(int counter[]){ 
	for (int i = 15; i >= 8; i-- ){
		counter[i] += 1;
		if( counter[i] < 10) break;
		else counter[i] = counter[i] - 10; 
	}
}
//子金鑰生成 
void keyExpansion(unsigned char Key[]){
	unsigned char tempByte[4];	
	unsigned char a0;
	
	//預先回合金鑰 
	for (int i = 0;i < Nk;i++){
        Roundkey[i * 4] = Key[i * 4];
        Roundkey[i * 4 + 1] = Key[i * 4 + 1];
        Roundkey[i * 4 + 2] = Key[i * 4 + 2];
        Roundkey[i * 4 + 3] = Key[i * 4 + 3];
    }
    
	//1~Nr回合金鑰 
	for (int i = Nk;i < (Nb * ( Nr + 1 ) );i++){
		
		for (int j = 0;j < 4;j++){ // 處理每個block(W)
            tempByte[j] = Roundkey[(i - 1) * 4 + j]; // 要新增一個block(Word)故取前一個的W值存入tempW
        }
        //AES-128, AES-192
		if (i % Nk ==0){
			// rotation 
			a0 = tempByte[0];
            tempByte[0] = tempByte[1];
            tempByte[1] = tempByte[2];
            tempByte[2] = tempByte[3];
            tempByte[3] = a0;
            // SubWord function
            tempByte[0] = getSBOX((int)tempByte[0]);
            tempByte[1] = getSBOX((int)tempByte[1]);
            tempByte[2] = getSBOX((int)tempByte[2]);
            tempByte[3] = getSBOX((int)tempByte[3]);
            
            //tempByte XOR [Rcon[i], 0, 0 ,0]
            tempByte[0] = tempByte[0] ^ Rcon[i / Nk - 1]; 
		}else if( Nk > 6 and i % Nk == 4 ){
			//use for AES-256
			//只做S-Box，不會做rotation 
			tempByte[0] = getSBOX((int)tempByte[0]);
            tempByte[1] = getSBOX((int)tempByte[1]);
            tempByte[2] = getSBOX((int)tempByte[2]);
            tempByte[3] = getSBOX((int)tempByte[3]);
		}
		
		Roundkey[i * 4 + 0] = Roundkey[(i - Nk) * 4 + 0] ^ tempByte[0];
        Roundkey[i * 4 + 1] = Roundkey[(i - Nk) * 4 + 1] ^ tempByte[1];
        Roundkey[i * 4 + 2] = Roundkey[(i - Nk) * 4 + 2] ^ tempByte[2];
        Roundkey[i * 4 + 3] = Roundkey[(i - Nk) * 4 + 3] ^ tempByte[3];   
    }
}
//AES加密主函式 
void AES_encrypt(){
	
	int round = 0;
	
	//明文區塊複製於 4 * 4 狀態陣列內  
	for (int i = 0;i < 4;i++)
        for (int j = 0;j < 4;j++)
            state[j][i] = input[i * 4 + j];//改成column major
    //start encryption
    //Round0
    
    addroundkey(0);
    //1~Nr
    for (round = 1;round < Nr;round++){
        SubBytes();
        ShiftRows();
        Mixcolumn();
        addroundkey(round);
	}
	
    //第Nr回合沒有Mixcolumn 
    SubBytes();
    ShiftRows();
    addroundkey(Nr);
	
    // 將狀態陣列複製到密文輸出陣列上
	for(int i = 0;i < 4;i++) 
        for(int j = 0;j < 4;j++)
            output[i * 4 + j] = state[j][i];// 改回一維陣列 
}
//解密主函式 
void AES_decrypt(){
	int round = Nr - 1;
	
	for (int i = 0;i < 4;i++)
        for (int j = 0;j < 4;j++)
            state[j][i] = input[i * 4 + j];//改成column major

	addroundkey(Nr);//first

	for (round = Nr - 1; round > 0; round-- ){
		ShiftRows_inv();
		SubBytes_inv();
		addroundkey(round);
		Mixcolumn_inv();
		
	}
	
	//last round, without mixcolumn_inv
    ShiftRows_inv();        	
    SubBytes_inv();
	addroundkey(0);
	
	for(int i = 0;i < 4;i++) 
        for(int j = 0;j < 4;j++)
            output[i * 4 + j] = state[j][i];// 改回一維陣列 
}
//AES加解密使用之函式 
void ShiftRows(){
	/*
	i為第幾行
	j為移動幾次 
	*/ 
    for (int i = 0; i < 4;   i++) {
		for (int j = 0; j < i;   j++) {
				int temp = state[i][0];
				state[i][0] = state[i][1];
				state[i][1] = state[i][2];
				state[i][2] = state[i][3];
				state[i][3] = temp;
		} 
	}
}
void ShiftRows_inv(){
	/*
	i為第幾行
	j為移動幾次 
	*/ 
    for (int i = 0; i < 4;   i++) {
		for (int j = 0; j < i;   j++) {
				int temp = state[i][3];
				state[i][3] = state[i][2];
				state[i][2] = state[i][1];
				state[i][1] = state[i][0];
				state[i][0] = temp;
		} 
	}
}
void Mixcolumn(){
	    for(int i = 0;i < 4;i++){    
    	byte a = state[0][i];
		byte b = state[1][i];
		byte c = state[2][i];
		byte d = state[3][i];
	
	    state[0][i] = Multiply(a, 0x02) ^ Multiply(b, 0x03) ^ c ^ d;
	    state[1][i] = a ^ Multiply(b, 0x02) ^ Multiply(c, 0x03) ^ d;
	    state[2][i] = a ^ b ^ Multiply(c, 0x02) ^ Multiply(d, 0x03);
	    state[3][i] = Multiply(a, 0x03) ^ b ^ c ^ Multiply(d, 0x02);
    }
}
void Mixcolumn_inv(){
	for (int i = 0; i < 4; ++i){ 
	    	byte a = state[0][i];
			byte b = state[1][i];
			byte c = state[2][i];
			byte d = state[3][i];
		
		    state[0][i] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
		    state[1][i] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
		    state[2][i] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
		    state[3][i] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
	}
}
void SubBytes(){
	/*呼叫getSBOX函式將對應位置的值取代原本的state*/ 
    for (int i = 0;i < 4;i++)
        for (int j = 0;j < 4;j++)
            state[i][j] = getSBOX(state[i][j]);
}
void SubBytes_inv(){
	/*呼叫getSBOX_inv函式將對應位置的值取代原本的state*/ 
    for (int i = 0;i < 4;i++)
        for (int j = 0;j < 4;j++)
            state[i][j] = getSBOX_inv(state[i][j]);
}
int getSBOX(int num){
    int sbox[256] =   {
    //	0	 1	   2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,//0 
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,//1 
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,//2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,//3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,//4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,//5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,//6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,//7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,//8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,//9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,//A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,//B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,//C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,//D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,//E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };//F
    return sbox[num];
}
int getSBOX_inv(int num){
    int inv_sbox[256] =   {
    //0      1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,//0 
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,//1
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,//2
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,//3
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,//4
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,//5
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,//6
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,//7
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,//8
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,//9 
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,//A 
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,//B
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,//C
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,//D
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,//E 
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};//F
    return inv_sbox[num];
}
void addroundkey(int round){	
	/**
     * 根據round來使用key(每次用1個block = 16byte)
     * first key index = round * 16 bytes = round * Nb * 4;
     * Nb = 4
     */
    
    for (int i = 0;i < 4;i++)
        for (int j = 0;j < 4;j++)
            state[j][i] ^= Roundkey[(i * Nb + j) + (round * Nb * 4)]; 
}
//查表加解密函式 
void AES_tbox_encrypt(){
	
	int round = 0;
	
	//明文區塊複製於 4 * 4 狀態陣列內  
	for (int i = 0;i < 4;i++)
        for (int j = 0;j < 4;j++)
            state[j][i] = input[i * 4 + j];//改成column major
            
    //start encryption
    //Round0
    addroundkey(0);
    //1 ~ Nr - 1
    for (round = 1; round < Nr; round++){
        ShiftRows();
        //查表版 
		for(int i = 0;i < 4; i++){    //4 * 8(char) = 32bit of a column 
	    	compress_col[i] = getTe0(state[0][i]) ^ \
							  getTe1(state[1][i]) ^ \
							  getTe2(state[2][i]) ^ \
							  getTe3(state[3][i]);
			//將column拆成4個byte 
			state[0][i] = (compress_col[i] >> 24) & 0xff;
			state[1][i] = (compress_col[i] >> 16) & 0xff;
			state[2][i] = (compress_col[i] >>  8) & 0xff;
			state[3][i] = (compress_col[i])       & 0xff;
   		}
   		addroundkey(round);
	}
        
    //第Nr回合沒有Mixcolumn 
    ShiftRows();
    SubBytes();
    addroundkey(Nr);
	
    // 將狀態陣列複製到密文輸出陣列上
	for(int i = 0;i < 4;i++) 
        for(int j = 0;j < 4;j++)
            output[i * 4 + j] = state[j][i];// 改回一維陣列 
}
void AES_tbox_decrypt(){
	
	//存第0輪擴展密鑰 
	byte round_key_reg[240] = {0};
	int round = Nr - 1;
	
	//明文區塊複製於 4 *4 狀態陣列內  
	for (int i = 0;i < 4;i++)
        for (int j = 0;j < 4;j++)
            state[j][i] = input[i * 4 + j];//改成column major
    
    //將Key 先做一次 mixColumn_inv 
    //1 ~ nr - 1 要mix_inv() 
    //做過mix_inv() ， tMix_inv_flag設為零 
    if(tMix_inv_flag) {
    	for (int i = 1; i <= round; i++){ 
    		for (int j = 0; j < 4; j++){
    			byte a = Roundkey[ (j * Nb    ) + (i * 16) ];
				byte b = Roundkey[ (j * Nb + 1) + (i * 16) ];
				byte c = Roundkey[ (j * Nb + 2) + (i * 16) ];
				byte d = Roundkey[ (j * Nb + 3) + (i * 16) ];
	
	    		Roundkey[ (j * Nb    ) + (i * 16) ] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
	    		Roundkey[ (j * Nb + 1) + (i * 16) ] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
	   	 		Roundkey[ (j * Nb + 2) + (i * 16) ] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
	    		Roundkey[ (j * Nb + 3) + (i * 16) ] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
			}
    	}
    	tMix_inv_flag = 0; //做完設為零 
	}
    
    //start decryption
    //Round Nr
	addroundkey(Nr);

	//Nr - 1 ~ 1
    for (round = Nr - 1; round > 0; round-- ){
		ShiftRows_inv();
		//查表解密 
		for(int i = 0; i < 4; i++){    //4 * 8(char) = 32bit of a column 
	    	compress_col[i] = getDe0(state[0][i]) ^ \
							  getDe1(state[1][i]) ^ \
							  getDe2(state[2][i]) ^ \
							  getDe3(state[3][i]);
			//將column拆成4個byte 
			state[0][i] = (compress_col[i] >> 24) & 0xff;
			state[1][i] = (compress_col[i] >> 16) & 0xff;
			state[2][i] = (compress_col[i] >>  8) & 0xff;
			state[3][i] = (compress_col[i])       & 0xff;
   		}

		addroundkey(round);

	}
	
	//第0回合沒有Mixcolumn 
	ShiftRows_inv();
    SubBytes_inv();
    //最後一次roundkey[0] 
    addroundkey(0);
    
    // 將狀態陣列複製到密文輸出陣列上
	for(int i = 0;i < 4;i++) 
        for(int j = 0;j < 4;j++)
            output[i * 4 + j] = state[j][i];// 改回一維陣列 
}
//查表加速版加密表 
int getTe0(int num){
    int te0[256] =   {
    0xc66363a5, 0xf87c7c84, 0xee777799, 0xf67b7b8d, 0xfff2f20d, 0xd66b6bbd, 0xde6f6fb1, 0x91c5c554, 
	0x60303050, 0x02010103, 0xce6767a9, 0x562b2b7d, 0xe7fefe19, 0xb5d7d762, 0x4dababe6, 0xec76769a, 
	0x8fcaca45, 0x1f82829d, 0x89c9c940, 0xfa7d7d87, 0xeffafa15, 0xb25959eb, 0x8e4747c9, 0xfbf0f00b, 
	0x41adadec, 0xb3d4d467, 0x5fa2a2fd, 0x45afafea, 0x239c9cbf, 0x53a4a4f7, 0xe4727296, 0x9bc0c05b, 
	0x75b7b7c2, 0xe1fdfd1c, 0x3d9393ae, 0x4c26266a, 0x6c36365a, 0x7e3f3f41, 0xf5f7f702, 0x83cccc4f, 
	0x6834345c, 0x51a5a5f4, 0xd1e5e534, 0xf9f1f108, 0xe2717193, 0xabd8d873, 0x62313153, 0x2a15153f, 
	0x0804040c, 0x95c7c752, 0x46232365, 0x9dc3c35e, 0x30181828, 0x379696a1, 0x0a05050f, 0x2f9a9ab5, 
	0x0e070709, 0x24121236, 0x1b80809b, 0xdfe2e23d, 0xcdebeb26, 0x4e272769, 0x7fb2b2cd, 0xea75759f, 
	0x1209091b, 0x1d83839e, 0x582c2c74, 0x341a1a2e, 0x361b1b2d, 0xdc6e6eb2, 0xb45a5aee, 0x5ba0a0fb, 
	0xa45252f6, 0x763b3b4d, 0xb7d6d661, 0x7db3b3ce, 0x5229297b, 0xdde3e33e, 0x5e2f2f71, 0x13848497, 
	0xa65353f5, 0xb9d1d168, 0x00000000, 0xc1eded2c, 0x40202060, 0xe3fcfc1f, 0x79b1b1c8, 0xb65b5bed, 
	0xd46a6abe, 0x8dcbcb46, 0x67bebed9, 0x7239394b, 0x944a4ade, 0x984c4cd4, 0xb05858e8, 0x85cfcf4a, 
	0xbbd0d06b, 0xc5efef2a, 0x4faaaae5, 0xedfbfb16, 0x864343c5, 0x9a4d4dd7, 0x66333355, 0x11858594, 
	0x8a4545cf, 0xe9f9f910, 0x04020206, 0xfe7f7f81, 0xa05050f0, 0x783c3c44, 0x259f9fba, 0x4ba8a8e3, 
	0xa25151f3, 0x5da3a3fe, 0x804040c0, 0x058f8f8a, 0x3f9292ad, 0x219d9dbc, 0x70383848, 0xf1f5f504, 
	0x63bcbcdf, 0x77b6b6c1, 0xafdada75, 0x42212163, 0x20101030, 0xe5ffff1a, 0xfdf3f30e, 0xbfd2d26d, 
	0x81cdcd4c, 0x180c0c14, 0x26131335, 0xc3ecec2f, 0xbe5f5fe1, 0x359797a2, 0x884444cc, 0x2e171739, 
	0x93c4c457, 0x55a7a7f2, 0xfc7e7e82, 0x7a3d3d47, 0xc86464ac, 0xba5d5de7, 0x3219192b, 0xe6737395, 
	0xc06060a0, 0x19818198, 0x9e4f4fd1, 0xa3dcdc7f, 0x44222266, 0x542a2a7e, 0x3b9090ab, 0x0b888883, 
	0x8c4646ca, 0xc7eeee29, 0x6bb8b8d3, 0x2814143c, 0xa7dede79, 0xbc5e5ee2, 0x160b0b1d, 0xaddbdb76, 
	0xdbe0e03b, 0x64323256, 0x743a3a4e, 0x140a0a1e, 0x924949db, 0x0c06060a, 0x4824246c, 0xb85c5ce4, 
	0x9fc2c25d, 0xbdd3d36e, 0x43acacef, 0xc46262a6, 0x399191a8, 0x319595a4, 0xd3e4e437, 0xf279798b, 
	0xd5e7e732, 0x8bc8c843, 0x6e373759, 0xda6d6db7, 0x018d8d8c, 0xb1d5d564, 0x9c4e4ed2, 0x49a9a9e0, 
	0xd86c6cb4, 0xac5656fa, 0xf3f4f407, 0xcfeaea25, 0xca6565af, 0xf47a7a8e, 0x47aeaee9, 0x10080818, 
	0x6fbabad5, 0xf0787888, 0x4a25256f, 0x5c2e2e72, 0x381c1c24, 0x57a6a6f1, 0x73b4b4c7, 0x97c6c651, 
	0xcbe8e823, 0xa1dddd7c, 0xe874749c, 0x3e1f1f21, 0x964b4bdd, 0x61bdbddc, 0x0d8b8b86, 0x0f8a8a85, 
	0xe0707090, 0x7c3e3e42, 0x71b5b5c4, 0xcc6666aa, 0x904848d8, 0x06030305, 0xf7f6f601, 0x1c0e0e12, 
	0xc26161a3, 0x6a35355f, 0xae5757f9, 0x69b9b9d0, 0x17868691, 0x99c1c158, 0x3a1d1d27, 0x279e9eb9, 
	0xd9e1e138, 0xebf8f813, 0x2b9898b3, 0x22111133, 0xd26969bb, 0xa9d9d970, 0x078e8e89, 0x339494a7, 
	0x2d9b9bb6, 0x3c1e1e22, 0x15878792, 0xc9e9e920, 0x87cece49, 0xaa5555ff, 0x50282878, 0xa5dfdf7a, 
	0x038c8c8f, 0x59a1a1f8, 0x09898980, 0x1a0d0d17, 0x65bfbfda, 0xd7e6e631, 0x844242c6, 0xd06868b8, 
	0x824141c3, 0x299999b0, 0x5a2d2d77, 0x1e0f0f11, 0x7bb0b0cb, 0xa85454fc, 0x6dbbbbd6, 0x2c16163a};
    return te0[num];
}
int getTe1(int num){
    int te1[256] =   {
    0xa5c66363, 0x84f87c7c, 0x99ee7777, 0x8df67b7b, 0x0dfff2f2, 0xbdd66b6b, 0xb1de6f6f, 0x5491c5c5, 
	0x50603030, 0x03020101, 0xa9ce6767, 0x7d562b2b, 0x19e7fefe, 0x62b5d7d7, 0xe64dabab, 0x9aec7676, 
	0x458fcaca, 0x9d1f8282, 0x4089c9c9, 0x87fa7d7d, 0x15effafa, 0xebb25959, 0xc98e4747, 0x0bfbf0f0, 
	0xec41adad, 0x67b3d4d4, 0xfd5fa2a2, 0xea45afaf, 0xbf239c9c, 0xf753a4a4, 0x96e47272, 0x5b9bc0c0, 
	0xc275b7b7, 0x1ce1fdfd, 0xae3d9393, 0x6a4c2626, 0x5a6c3636, 0x417e3f3f, 0x02f5f7f7, 0x4f83cccc, 
	0x5c683434, 0xf451a5a5, 0x34d1e5e5, 0x08f9f1f1, 0x93e27171, 0x73abd8d8, 0x53623131, 0x3f2a1515, 
	0x0c080404, 0x5295c7c7, 0x65462323, 0x5e9dc3c3, 0x28301818, 0xa1379696, 0x0f0a0505, 0xb52f9a9a, 
	0x090e0707, 0x36241212, 0x9b1b8080, 0x3ddfe2e2, 0x26cdebeb, 0x694e2727, 0xcd7fb2b2, 0x9fea7575, 
	0x1b120909, 0x9e1d8383, 0x74582c2c, 0x2e341a1a, 0x2d361b1b, 0xb2dc6e6e, 0xeeb45a5a, 0xfb5ba0a0, 
	0xf6a45252, 0x4d763b3b, 0x61b7d6d6, 0xce7db3b3, 0x7b522929, 0x3edde3e3, 0x715e2f2f, 0x97138484, 
	0xf5a65353, 0x68b9d1d1, 0x00000000, 0x2cc1eded, 0x60402020, 0x1fe3fcfc, 0xc879b1b1, 0xedb65b5b, 
	0xbed46a6a, 0x468dcbcb, 0xd967bebe, 0x4b723939, 0xde944a4a, 0xd4984c4c, 0xe8b05858, 0x4a85cfcf, 
	0x6bbbd0d0, 0x2ac5efef, 0xe54faaaa, 0x16edfbfb, 0xc5864343, 0xd79a4d4d, 0x55663333, 0x94118585, 
	0xcf8a4545, 0x10e9f9f9, 0x06040202, 0x81fe7f7f, 0xf0a05050, 0x44783c3c, 0xba259f9f, 0xe34ba8a8, 
	0xf3a25151, 0xfe5da3a3, 0xc0804040, 0x8a058f8f, 0xad3f9292, 0xbc219d9d, 0x48703838, 0x04f1f5f5, 
	0xdf63bcbc, 0xc177b6b6, 0x75afdada, 0x63422121, 0x30201010, 0x1ae5ffff, 0x0efdf3f3, 0x6dbfd2d2, 
	0x4c81cdcd, 0x14180c0c, 0x35261313, 0x2fc3ecec, 0xe1be5f5f, 0xa2359797, 0xcc884444, 0x392e1717, 
	0x5793c4c4, 0xf255a7a7, 0x82fc7e7e, 0x477a3d3d, 0xacc86464, 0xe7ba5d5d, 0x2b321919, 0x95e67373, 
	0xa0c06060, 0x98198181, 0xd19e4f4f, 0x7fa3dcdc, 0x66442222, 0x7e542a2a, 0xab3b9090, 0x830b8888, 
	0xca8c4646, 0x29c7eeee, 0xd36bb8b8, 0x3c281414, 0x79a7dede, 0xe2bc5e5e, 0x1d160b0b, 0x76addbdb, 
	0x3bdbe0e0, 0x56643232, 0x4e743a3a, 0x1e140a0a, 0xdb924949, 0x0a0c0606, 0x6c482424, 0xe4b85c5c, 
	0x5d9fc2c2, 0x6ebdd3d3, 0xef43acac, 0xa6c46262, 0xa8399191, 0xa4319595, 0x37d3e4e4, 0x8bf27979, 
	0x32d5e7e7, 0x438bc8c8, 0x596e3737, 0xb7da6d6d, 0x8c018d8d, 0x64b1d5d5, 0xd29c4e4e, 0xe049a9a9, 
	0xb4d86c6c, 0xfaac5656, 0x07f3f4f4, 0x25cfeaea, 0xafca6565, 0x8ef47a7a, 0xe947aeae, 0x18100808, 
	0xd56fbaba, 0x88f07878, 0x6f4a2525, 0x725c2e2e, 0x24381c1c, 0xf157a6a6, 0xc773b4b4, 0x5197c6c6, 
	0x23cbe8e8, 0x7ca1dddd, 0x9ce87474, 0x213e1f1f, 0xdd964b4b, 0xdc61bdbd, 0x860d8b8b, 0x850f8a8a, 
	0x90e07070, 0x427c3e3e, 0xc471b5b5, 0xaacc6666, 0xd8904848, 0x05060303, 0x01f7f6f6, 0x121c0e0e, 
	0xa3c26161, 0x5f6a3535, 0xf9ae5757, 0xd069b9b9, 0x91178686, 0x5899c1c1, 0x273a1d1d, 0xb9279e9e, 
	0x38d9e1e1, 0x13ebf8f8, 0xb32b9898, 0x33221111, 0xbbd26969, 0x70a9d9d9, 0x89078e8e, 0xa7339494, 
	0xb62d9b9b, 0x223c1e1e, 0x92158787, 0x20c9e9e9, 0x4987cece, 0xffaa5555, 0x78502828, 0x7aa5dfdf, 
	0x8f038c8c, 0xf859a1a1, 0x80098989, 0x171a0d0d, 0xda65bfbf, 0x31d7e6e6, 0xc6844242, 0xb8d06868, 
	0xc3824141, 0xb0299999, 0x775a2d2d, 0x111e0f0f, 0xcb7bb0b0, 0xfca85454, 0xd66dbbbb, 0x3a2c1616};
    return te1[num];
}
int getTe2(int num){
    int te2[256] =   {
    0x63a5c663, 0x7c84f87c, 0x7799ee77, 0x7b8df67b, 0xf20dfff2, 0x6bbdd66b, 0x6fb1de6f, 0xc55491c5, 
	0x30506030, 0x01030201, 0x67a9ce67, 0x2b7d562b, 0xfe19e7fe, 0xd762b5d7, 0xabe64dab, 0x769aec76, 
	0xca458fca, 0x829d1f82, 0xc94089c9, 0x7d87fa7d, 0xfa15effa, 0x59ebb259, 0x47c98e47, 0xf00bfbf0, 
	0xadec41ad, 0xd467b3d4, 0xa2fd5fa2, 0xafea45af, 0x9cbf239c, 0xa4f753a4, 0x7296e472, 0xc05b9bc0, 
	0xb7c275b7, 0xfd1ce1fd, 0x93ae3d93, 0x266a4c26, 0x365a6c36, 0x3f417e3f, 0xf702f5f7, 0xcc4f83cc, 
	0x345c6834, 0xa5f451a5, 0xe534d1e5, 0xf108f9f1, 0x7193e271, 0xd873abd8, 0x31536231, 0x153f2a15, 
	0x040c0804, 0xc75295c7, 0x23654623, 0xc35e9dc3, 0x18283018, 0x96a13796, 0x050f0a05, 0x9ab52f9a, 
	0x07090e07, 0x12362412, 0x809b1b80, 0xe23ddfe2, 0xeb26cdeb, 0x27694e27, 0xb2cd7fb2, 0x759fea75, 
	0x091b1209, 0x839e1d83, 0x2c74582c, 0x1a2e341a, 0x1b2d361b, 0x6eb2dc6e, 0x5aeeb45a, 0xa0fb5ba0, 
	0x52f6a452, 0x3b4d763b, 0xd661b7d6, 0xb3ce7db3, 0x297b5229, 0xe33edde3, 0x2f715e2f, 0x84971384, 
	0x53f5a653, 0xd168b9d1, 0x00000000, 0xed2cc1ed, 0x20604020, 0xfc1fe3fc, 0xb1c879b1, 0x5bedb65b, 
	0x6abed46a, 0xcb468dcb, 0xbed967be, 0x394b7239, 0x4ade944a, 0x4cd4984c, 0x58e8b058, 0xcf4a85cf, 
	0xd06bbbd0, 0xef2ac5ef, 0xaae54faa, 0xfb16edfb, 0x43c58643, 0x4dd79a4d, 0x33556633, 0x85941185, 
	0x45cf8a45, 0xf910e9f9, 0x02060402, 0x7f81fe7f, 0x50f0a050, 0x3c44783c, 0x9fba259f, 0xa8e34ba8, 
	0x51f3a251, 0xa3fe5da3, 0x40c08040, 0x8f8a058f, 0x92ad3f92, 0x9dbc219d, 0x38487038, 0xf504f1f5, 
	0xbcdf63bc, 0xb6c177b6, 0xda75afda, 0x21634221, 0x10302010, 0xff1ae5ff, 0xf30efdf3, 0xd26dbfd2, 
	0xcd4c81cd, 0x0c14180c, 0x13352613, 0xec2fc3ec, 0x5fe1be5f, 0x97a23597, 0x44cc8844, 0x17392e17, 
	0xc45793c4, 0xa7f255a7, 0x7e82fc7e, 0x3d477a3d, 0x64acc864, 0x5de7ba5d, 0x192b3219, 0x7395e673, 
	0x60a0c060, 0x81981981, 0x4fd19e4f, 0xdc7fa3dc, 0x22664422, 0x2a7e542a, 0x90ab3b90, 0x88830b88, 
	0x46ca8c46, 0xee29c7ee, 0xb8d36bb8, 0x143c2814, 0xde79a7de, 0x5ee2bc5e, 0x0b1d160b, 0xdb76addb, 
	0xe03bdbe0, 0x32566432, 0x3a4e743a, 0x0a1e140a, 0x49db9249, 0x060a0c06, 0x246c4824, 0x5ce4b85c, 
	0xc25d9fc2, 0xd36ebdd3, 0xacef43ac, 0x62a6c462, 0x91a83991, 0x95a43195, 0xe437d3e4, 0x798bf279, 
	0xe732d5e7, 0xc8438bc8, 0x37596e37, 0x6db7da6d, 0x8d8c018d, 0xd564b1d5, 0x4ed29c4e, 0xa9e049a9, 
	0x6cb4d86c, 0x56faac56, 0xf407f3f4, 0xea25cfea, 0x65afca65, 0x7a8ef47a, 0xaee947ae, 0x08181008, 
	0xbad56fba, 0x7888f078, 0x256f4a25, 0x2e725c2e, 0x1c24381c, 0xa6f157a6, 0xb4c773b4, 0xc65197c6, 
	0xe823cbe8, 0xdd7ca1dd, 0x749ce874, 0x1f213e1f, 0x4bdd964b, 0xbddc61bd, 0x8b860d8b, 0x8a850f8a, 
	0x7090e070, 0x3e427c3e, 0xb5c471b5, 0x66aacc66, 0x48d89048, 0x03050603, 0xf601f7f6, 0x0e121c0e, 
	0x61a3c261, 0x355f6a35, 0x57f9ae57, 0xb9d069b9, 0x86911786, 0xc15899c1, 0x1d273a1d, 0x9eb9279e, 
	0xe138d9e1, 0xf813ebf8, 0x98b32b98, 0x11332211, 0x69bbd269, 0xd970a9d9, 0x8e89078e, 0x94a73394, 
	0x9bb62d9b, 0x1e223c1e, 0x87921587, 0xe920c9e9, 0xce4987ce, 0x55ffaa55, 0x28785028, 0xdf7aa5df, 
	0x8c8f038c, 0xa1f859a1, 0x89800989, 0x0d171a0d, 0xbfda65bf, 0xe631d7e6, 0x42c68442, 0x68b8d068, 
	0x41c38241, 0x99b02999, 0x2d775a2d, 0x0f111e0f, 0xb0cb7bb0, 0x54fca854, 0xbbd66dbb, 0x163a2c16};
    return te2[num];
}
int getTe3(int num){
    int te3[256] =   {
    0x6363a5c6, 0x7c7c84f8, 0x777799ee, 0x7b7b8df6, 0xf2f20dff, 0x6b6bbdd6, 0x6f6fb1de, 0xc5c55491, 
	0x30305060, 0x01010302, 0x6767a9ce, 0x2b2b7d56, 0xfefe19e7, 0xd7d762b5, 0xababe64d, 0x76769aec, 
	0xcaca458f, 0x82829d1f, 0xc9c94089, 0x7d7d87fa, 0xfafa15ef, 0x5959ebb2, 0x4747c98e, 0xf0f00bfb, 
	0xadadec41, 0xd4d467b3, 0xa2a2fd5f, 0xafafea45, 0x9c9cbf23, 0xa4a4f753, 0x727296e4, 0xc0c05b9b, 
	0xb7b7c275, 0xfdfd1ce1, 0x9393ae3d, 0x26266a4c, 0x36365a6c, 0x3f3f417e, 0xf7f702f5, 0xcccc4f83, 
	0x34345c68, 0xa5a5f451, 0xe5e534d1, 0xf1f108f9, 0x717193e2, 0xd8d873ab, 0x31315362, 0x15153f2a, 
	0x04040c08, 0xc7c75295, 0x23236546, 0xc3c35e9d, 0x18182830, 0x9696a137, 0x05050f0a, 0x9a9ab52f, 
	0x0707090e, 0x12123624, 0x80809b1b, 0xe2e23ddf, 0xebeb26cd, 0x2727694e, 0xb2b2cd7f, 0x75759fea, 
	0x09091b12, 0x83839e1d, 0x2c2c7458, 0x1a1a2e34, 0x1b1b2d36, 0x6e6eb2dc, 0x5a5aeeb4, 0xa0a0fb5b, 
	0x5252f6a4, 0x3b3b4d76, 0xd6d661b7, 0xb3b3ce7d, 0x29297b52, 0xe3e33edd, 0x2f2f715e, 0x84849713, 
	0x5353f5a6, 0xd1d168b9, 0x00000000, 0xeded2cc1, 0x20206040, 0xfcfc1fe3, 0xb1b1c879, 0x5b5bedb6, 
	0x6a6abed4, 0xcbcb468d, 0xbebed967, 0x39394b72, 0x4a4ade94, 0x4c4cd498, 0x5858e8b0, 0xcfcf4a85, 
	0xd0d06bbb, 0xefef2ac5, 0xaaaae54f, 0xfbfb16ed, 0x4343c586, 0x4d4dd79a, 0x33335566, 0x85859411, 
	0x4545cf8a, 0xf9f910e9, 0x02020604, 0x7f7f81fe, 0x5050f0a0, 0x3c3c4478, 0x9f9fba25, 0xa8a8e34b, 
	0x5151f3a2, 0xa3a3fe5d, 0x4040c080, 0x8f8f8a05, 0x9292ad3f, 0x9d9dbc21, 0x38384870, 0xf5f504f1, 
	0xbcbcdf63, 0xb6b6c177, 0xdada75af, 0x21216342, 0x10103020, 0xffff1ae5, 0xf3f30efd, 0xd2d26dbf, 
	0xcdcd4c81, 0x0c0c1418, 0x13133526, 0xecec2fc3, 0x5f5fe1be, 0x9797a235, 0x4444cc88, 0x1717392e, 
	0xc4c45793, 0xa7a7f255, 0x7e7e82fc, 0x3d3d477a, 0x6464acc8, 0x5d5de7ba, 0x19192b32, 0x737395e6, 
	0x6060a0c0, 0x81819819, 0x4f4fd19e, 0xdcdc7fa3, 0x22226644, 0x2a2a7e54, 0x9090ab3b, 0x8888830b, 
	0x4646ca8c, 0xeeee29c7, 0xb8b8d36b, 0x14143c28, 0xdede79a7, 0x5e5ee2bc, 0x0b0b1d16, 0xdbdb76ad, 
	0xe0e03bdb, 0x32325664, 0x3a3a4e74, 0x0a0a1e14, 0x4949db92, 0x06060a0c, 0x24246c48, 0x5c5ce4b8, 
	0xc2c25d9f, 0xd3d36ebd, 0xacacef43, 0x6262a6c4, 0x9191a839, 0x9595a431, 0xe4e437d3, 0x79798bf2, 
	0xe7e732d5, 0xc8c8438b, 0x3737596e, 0x6d6db7da, 0x8d8d8c01, 0xd5d564b1, 0x4e4ed29c, 0xa9a9e049, 
	0x6c6cb4d8, 0x5656faac, 0xf4f407f3, 0xeaea25cf, 0x6565afca, 0x7a7a8ef4, 0xaeaee947, 0x08081810, 
	0xbabad56f, 0x787888f0, 0x25256f4a, 0x2e2e725c, 0x1c1c2438, 0xa6a6f157, 0xb4b4c773, 0xc6c65197, 
	0xe8e823cb, 0xdddd7ca1, 0x74749ce8, 0x1f1f213e, 0x4b4bdd96, 0xbdbddc61, 0x8b8b860d, 0x8a8a850f, 
	0x707090e0, 0x3e3e427c, 0xb5b5c471, 0x6666aacc, 0x4848d890, 0x03030506, 0xf6f601f7, 0x0e0e121c, 
	0x6161a3c2, 0x35355f6a, 0x5757f9ae, 0xb9b9d069, 0x86869117, 0xc1c15899, 0x1d1d273a, 0x9e9eb927, 
	0xe1e138d9, 0xf8f813eb, 0x9898b32b, 0x11113322, 0x6969bbd2, 0xd9d970a9, 0x8e8e8907, 0x9494a733, 
	0x9b9bb62d, 0x1e1e223c, 0x87879215, 0xe9e920c9, 0xcece4987, 0x5555ffaa, 0x28287850, 0xdfdf7aa5, 
	0x8c8c8f03, 0xa1a1f859, 0x89898009, 0x0d0d171a, 0xbfbfda65, 0xe6e631d7, 0x4242c684, 0x6868b8d0, 
	0x4141c382, 0x9999b029, 0x2d2d775a, 0x0f0f111e, 0xb0b0cb7b, 0x5454fca8, 0xbbbbd66d, 0x16163a2c};
    return te3[num];
}
//查表加速解密表 
int getDe0(int num){
    int de0[256] =   {
    0x51f4a750, 0x7e416553, 0x1a17a4c3, 0x3a275e96, 0x3bab6bcb, 0x1f9d45f1, 0xacfa58ab, 0x4be30393, 
	0x2030fa55, 0xad766df6, 0x88cc7691, 0xf5024c25, 0x4fe5d7fc, 0xc52acbd7, 0x26354480, 0xb562a38f, 
	0xdeb15a49, 0x25ba1b67, 0x45ea0e98, 0x5dfec0e1, 0xc32f7502, 0x814cf012, 0x8d4697a3, 0x6bd3f9c6, 
	0x038f5fe7, 0x15929c95, 0xbf6d7aeb, 0x955259da, 0xd4be832d, 0x587421d3, 0x49e06929, 0x8ec9c844, 
	0x75c2896a, 0xf48e7978, 0x99583e6b, 0x27b971dd, 0xbee14fb6, 0xf088ad17, 0xc920ac66, 0x7dce3ab4, 
	0x63df4a18, 0xe51a3182, 0x97513360, 0x62537f45, 0xb16477e0, 0xbb6bae84, 0xfe81a01c, 0xf9082b94, 
	0x70486858, 0x8f45fd19, 0x94de6c87, 0x527bf8b7, 0xab73d323, 0x724b02e2, 0xe31f8f57, 0x6655ab2a, 
	0xb2eb2807, 0x2fb5c203, 0x86c57b9a, 0xd33708a5, 0x302887f2, 0x23bfa5b2, 0x02036aba, 0xed16825c, 
	0x8acf1c2b, 0xa779b492, 0xf307f2f0, 0x4e69e2a1, 0x65daf4cd, 0x0605bed5, 0xd134621f, 0xc4a6fe8a, 
	0x342e539d, 0xa2f355a0, 0x058ae132, 0xa4f6eb75, 0x0b83ec39, 0x4060efaa, 0x5e719f06, 0xbd6e1051, 
	0x3e218af9, 0x96dd063d, 0xdd3e05ae, 0x4de6bd46, 0x91548db5, 0x71c45d05, 0x0406d46f, 0x605015ff, 
	0x1998fb24, 0xd6bde997, 0x894043cc, 0x67d99e77, 0xb0e842bd, 0x07898b88, 0xe7195b38, 0x79c8eedb, 
	0xa17c0a47, 0x7c420fe9, 0xf8841ec9, 0x00000000, 0x09808683, 0x322bed48, 0x1e1170ac, 0x6c5a724e, 
	0xfd0efffb, 0x0f853856, 0x3daed51e, 0x362d3927, 0x0a0fd964, 0x685ca621, 0x9b5b54d1, 0x24362e3a, 
	0x0c0a67b1, 0x9357e70f, 0xb4ee96d2, 0x1b9b919e, 0x80c0c54f, 0x61dc20a2, 0x5a774b69, 0x1c121a16, 
	0xe293ba0a, 0xc0a02ae5, 0x3c22e043, 0x121b171d, 0x0e090d0b, 0xf28bc7ad, 0x2db6a8b9, 0x141ea9c8, 
	0x57f11985, 0xaf75074c, 0xee99ddbb, 0xa37f60fd, 0xf701269f, 0x5c72f5bc, 0x44663bc5, 0x5bfb7e34, 
	0x8b432976, 0xcb23c6dc, 0xb6edfc68, 0xb8e4f163, 0xd731dcca, 0x42638510, 0x13972240, 0x84c61120, 
	0x854a247d, 0xd2bb3df8, 0xaef93211, 0xc729a16d, 0x1d9e2f4b, 0xdcb230f3, 0x0d8652ec, 0x77c1e3d0, 
	0x2bb3166c, 0xa970b999, 0x119448fa, 0x47e96422, 0xa8fc8cc4, 0xa0f03f1a, 0x567d2cd8, 0x223390ef, 
	0x87494ec7, 0xd938d1c1, 0x8ccaa2fe, 0x98d40b36, 0xa6f581cf, 0xa57ade28, 0xdab78e26, 0x3fadbfa4, 
	0x2c3a9de4, 0x5078920d, 0x6a5fcc9b, 0x547e4662, 0xf68d13c2, 0x90d8b8e8, 0x2e39f75e, 0x82c3aff5, 
	0x9f5d80be, 0x69d0937c, 0x6fd52da9, 0xcf2512b3, 0xc8ac993b, 0x10187da7, 0xe89c636e, 0xdb3bbb7b, 
	0xcd267809, 0x6e5918f4, 0xec9ab701, 0x834f9aa8, 0xe6956e65, 0xaaffe67e, 0x21bccf08, 0xef15e8e6, 
	0xbae79bd9, 0x4a6f36ce, 0xea9f09d4, 0x29b07cd6, 0x31a4b2af, 0x2a3f2331, 0xc6a59430, 0x35a266c0, 
	0x744ebc37, 0xfc82caa6, 0xe090d0b0, 0x33a7d815, 0xf104984a, 0x41ecdaf7, 0x7fcd500e, 0x1791f62f, 
	0x764dd68d, 0x43efb04d, 0xccaa4d54, 0xe49604df, 0x9ed1b5e3, 0x4c6a881b, 0xc12c1fb8, 0x4665517f, 
	0x9d5eea04, 0x018c355d, 0xfa877473, 0xfb0b412e, 0xb3671d5a, 0x92dbd252, 0xe9105633, 0x6dd64713, 
	0x9ad7618c, 0x37a10c7a, 0x59f8148e, 0xeb133c89, 0xcea927ee, 0xb761c935, 0xe11ce5ed, 0x7a47b13c, 
	0x9cd2df59, 0x55f2733f, 0x1814ce79, 0x73c737bf, 0x53f7cdea, 0x5ffdaa5b, 0xdf3d6f14, 0x7844db86, 
	0xcaaff381, 0xb968c43e, 0x3824342c, 0xc2a3405f, 0x161dc372, 0xbce2250c, 0x283c498b, 0xff0d9541, 
	0x39a80171, 0x080cb3de, 0xd8b4e49c, 0x6456c190, 0x7bcb8461, 0xd532b670, 0x486c5c74, 0xd0b85742};
    return de0[num];
}
int getDe1(int num){
    int de1[256] =   {
    0x5051f4a7, 0x537e4165, 0xc31a17a4, 0x963a275e, 0xcb3bab6b, 0xf11f9d45, 0xabacfa58, 0x934be303, 
	0x552030fa, 0xf6ad766d, 0x9188cc76, 0x25f5024c, 0xfc4fe5d7, 0xd7c52acb, 0x80263544, 0x8fb562a3, 
	0x49deb15a, 0x6725ba1b, 0x9845ea0e, 0xe15dfec0, 0x02c32f75, 0x12814cf0, 0xa38d4697, 0xc66bd3f9, 
	0xe7038f5f, 0x9515929c, 0xebbf6d7a, 0xda955259, 0x2dd4be83, 0xd3587421, 0x2949e069, 0x448ec9c8, 
	0x6a75c289, 0x78f48e79, 0x6b99583e, 0xdd27b971, 0xb6bee14f, 0x17f088ad, 0x66c920ac, 0xb47dce3a, 
	0x1863df4a, 0x82e51a31, 0x60975133, 0x4562537f, 0xe0b16477, 0x84bb6bae, 0x1cfe81a0, 0x94f9082b, 
	0x58704868, 0x198f45fd, 0x8794de6c, 0xb7527bf8, 0x23ab73d3, 0xe2724b02, 0x57e31f8f, 0x2a6655ab, 
	0x07b2eb28, 0x032fb5c2, 0x9a86c57b, 0xa5d33708, 0xf2302887, 0xb223bfa5, 0xba02036a, 0x5ced1682, 
	0x2b8acf1c, 0x92a779b4, 0xf0f307f2, 0xa14e69e2, 0xcd65daf4, 0xd50605be, 0x1fd13462, 0x8ac4a6fe, 
	0x9d342e53, 0xa0a2f355, 0x32058ae1, 0x75a4f6eb, 0x390b83ec, 0xaa4060ef, 0x065e719f, 0x51bd6e10, 
	0xf93e218a, 0x3d96dd06, 0xaedd3e05, 0x464de6bd, 0xb591548d, 0x0571c45d, 0x6f0406d4, 0xff605015, 
	0x241998fb, 0x97d6bde9, 0xcc894043, 0x7767d99e, 0xbdb0e842, 0x8807898b, 0x38e7195b, 0xdb79c8ee, 
	0x47a17c0a, 0xe97c420f, 0xc9f8841e, 0x00000000, 0x83098086, 0x48322bed, 0xac1e1170, 0x4e6c5a72, 
	0xfbfd0eff, 0x560f8538, 0x1e3daed5, 0x27362d39, 0x640a0fd9, 0x21685ca6, 0xd19b5b54, 0x3a24362e, 
	0xb10c0a67, 0x0f9357e7, 0xd2b4ee96, 0x9e1b9b91, 0x4f80c0c5, 0xa261dc20, 0x695a774b, 0x161c121a, 
	0x0ae293ba, 0xe5c0a02a, 0x433c22e0, 0x1d121b17, 0x0b0e090d, 0xadf28bc7, 0xb92db6a8, 0xc8141ea9, 
	0x8557f119, 0x4caf7507, 0xbbee99dd, 0xfda37f60, 0x9ff70126, 0xbc5c72f5, 0xc544663b, 0x345bfb7e, 
	0x768b4329, 0xdccb23c6, 0x68b6edfc, 0x63b8e4f1, 0xcad731dc, 0x10426385, 0x40139722, 0x2084c611, 
	0x7d854a24, 0xf8d2bb3d, 0x11aef932, 0x6dc729a1, 0x4b1d9e2f, 0xf3dcb230, 0xec0d8652, 0xd077c1e3, 
	0x6c2bb316, 0x99a970b9, 0xfa119448, 0x2247e964, 0xc4a8fc8c, 0x1aa0f03f, 0xd8567d2c, 0xef223390, 
	0xc787494e, 0xc1d938d1, 0xfe8ccaa2, 0x3698d40b, 0xcfa6f581, 0x28a57ade, 0x26dab78e, 0xa43fadbf, 
	0xe42c3a9d, 0x0d507892, 0x9b6a5fcc, 0x62547e46, 0xc2f68d13, 0xe890d8b8, 0x5e2e39f7, 0xf582c3af, 
	0xbe9f5d80, 0x7c69d093, 0xa96fd52d, 0xb3cf2512, 0x3bc8ac99, 0xa710187d, 0x6ee89c63, 0x7bdb3bbb, 
	0x09cd2678, 0xf46e5918, 0x01ec9ab7, 0xa8834f9a, 0x65e6956e, 0x7eaaffe6, 0x0821bccf, 0xe6ef15e8, 
	0xd9bae79b, 0xce4a6f36, 0xd4ea9f09, 0xd629b07c, 0xaf31a4b2, 0x312a3f23, 0x30c6a594, 0xc035a266, 
	0x37744ebc, 0xa6fc82ca, 0xb0e090d0, 0x1533a7d8, 0x4af10498, 0xf741ecda, 0x0e7fcd50, 0x2f1791f6, 
	0x8d764dd6, 0x4d43efb0, 0x54ccaa4d, 0xdfe49604, 0xe39ed1b5, 0x1b4c6a88, 0xb8c12c1f, 0x7f466551, 
	0x049d5eea, 0x5d018c35, 0x73fa8774, 0x2efb0b41, 0x5ab3671d, 0x5292dbd2, 0x33e91056, 0x136dd647, 
	0x8c9ad761, 0x7a37a10c, 0x8e59f814, 0x89eb133c, 0xeecea927, 0x35b761c9, 0xede11ce5, 0x3c7a47b1, 
	0x599cd2df, 0x3f55f273, 0x791814ce, 0xbf73c737, 0xea53f7cd, 0x5b5ffdaa, 0x14df3d6f, 0x867844db, 
	0x81caaff3, 0x3eb968c4, 0x2c382434, 0x5fc2a340, 0x72161dc3, 0x0cbce225, 0x8b283c49, 0x41ff0d95, 
	0x7139a801, 0xde080cb3, 0x9cd8b4e4, 0x906456c1, 0x617bcb84, 0x70d532b6, 0x74486c5c, 0x42d0b857};
    return de1[num];
}
int getDe2(int num){
    int de2[256] =   {
    0xa75051f4, 0x65537e41, 0xa4c31a17, 0x5e963a27, 0x6bcb3bab, 0x45f11f9d, 0x58abacfa, 0x03934be3, 
	0xfa552030, 0x6df6ad76, 0x769188cc, 0x4c25f502, 0xd7fc4fe5, 0xcbd7c52a, 0x44802635, 0xa38fb562, 
	0x5a49deb1, 0x1b6725ba, 0x0e9845ea, 0xc0e15dfe, 0x7502c32f, 0xf012814c, 0x97a38d46, 0xf9c66bd3, 
	0x5fe7038f, 0x9c951592, 0x7aebbf6d, 0x59da9552, 0x832dd4be, 0x21d35874, 0x692949e0, 0xc8448ec9, 
	0x896a75c2, 0x7978f48e, 0x3e6b9958, 0x71dd27b9, 0x4fb6bee1, 0xad17f088, 0xac66c920, 0x3ab47dce, 
	0x4a1863df, 0x3182e51a, 0x33609751, 0x7f456253, 0x77e0b164, 0xae84bb6b, 0xa01cfe81, 0x2b94f908, 
	0x68587048, 0xfd198f45, 0x6c8794de, 0xf8b7527b, 0xd323ab73, 0x02e2724b, 0x8f57e31f, 0xab2a6655, 
	0x2807b2eb, 0xc2032fb5, 0x7b9a86c5, 0x08a5d337, 0x87f23028, 0xa5b223bf, 0x6aba0203, 0x825ced16, 
	0x1c2b8acf, 0xb492a779, 0xf2f0f307, 0xe2a14e69, 0xf4cd65da, 0xbed50605, 0x621fd134, 0xfe8ac4a6, 
	0x539d342e, 0x55a0a2f3, 0xe132058a, 0xeb75a4f6, 0xec390b83, 0xefaa4060, 0x9f065e71, 0x1051bd6e, 
	0x8af93e21, 0x063d96dd, 0x05aedd3e, 0xbd464de6, 0x8db59154, 0x5d0571c4, 0xd46f0406, 0x15ff6050, 
	0xfb241998, 0xe997d6bd, 0x43cc8940, 0x9e7767d9, 0x42bdb0e8, 0x8b880789, 0x5b38e719, 0xeedb79c8, 
	0x0a47a17c, 0x0fe97c42, 0x1ec9f884, 0x00000000, 0x86830980, 0xed48322b, 0x70ac1e11, 0x724e6c5a, 
	0xfffbfd0e, 0x38560f85, 0xd51e3dae, 0x3927362d, 0xd9640a0f, 0xa621685c, 0x54d19b5b, 0x2e3a2436, 
	0x67b10c0a, 0xe70f9357, 0x96d2b4ee, 0x919e1b9b, 0xc54f80c0, 0x20a261dc, 0x4b695a77, 0x1a161c12, 
	0xba0ae293, 0x2ae5c0a0, 0xe0433c22, 0x171d121b, 0x0d0b0e09, 0xc7adf28b, 0xa8b92db6, 0xa9c8141e, 
	0x198557f1, 0x074caf75, 0xddbbee99, 0x60fda37f, 0x269ff701, 0xf5bc5c72, 0x3bc54466, 0x7e345bfb, 
	0x29768b43, 0xc6dccb23, 0xfc68b6ed, 0xf163b8e4, 0xdccad731, 0x85104263, 0x22401397, 0x112084c6, 
	0x247d854a, 0x3df8d2bb, 0x3211aef9, 0xa16dc729, 0x2f4b1d9e, 0x30f3dcb2, 0x52ec0d86, 0xe3d077c1, 
	0x166c2bb3, 0xb999a970, 0x48fa1194, 0x642247e9, 0x8cc4a8fc, 0x3f1aa0f0, 0x2cd8567d, 0x90ef2233, 
	0x4ec78749, 0xd1c1d938, 0xa2fe8cca, 0x0b3698d4, 0x81cfa6f5, 0xde28a57a, 0x8e26dab7, 0xbfa43fad, 
	0x9de42c3a, 0x920d5078, 0xcc9b6a5f, 0x4662547e, 0x13c2f68d, 0xb8e890d8, 0xf75e2e39, 0xaff582c3, 
	0x80be9f5d, 0x937c69d0, 0x2da96fd5, 0x12b3cf25, 0x993bc8ac, 0x7da71018, 0x636ee89c, 0xbb7bdb3b, 
	0x7809cd26, 0x18f46e59, 0xb701ec9a, 0x9aa8834f, 0x6e65e695, 0xe67eaaff, 0xcf0821bc, 0xe8e6ef15, 
	0x9bd9bae7, 0x36ce4a6f, 0x09d4ea9f, 0x7cd629b0, 0xb2af31a4, 0x23312a3f, 0x9430c6a5, 0x66c035a2, 
	0xbc37744e, 0xcaa6fc82, 0xd0b0e090, 0xd81533a7, 0x984af104, 0xdaf741ec, 0x500e7fcd, 0xf62f1791, 
	0xd68d764d, 0xb04d43ef, 0x4d54ccaa, 0x04dfe496, 0xb5e39ed1, 0x881b4c6a, 0x1fb8c12c, 0x517f4665, 
	0xea049d5e, 0x355d018c, 0x7473fa87, 0x412efb0b, 0x1d5ab367, 0xd25292db, 0x5633e910, 0x47136dd6, 
	0x618c9ad7, 0x0c7a37a1, 0x148e59f8, 0x3c89eb13, 0x27eecea9, 0xc935b761, 0xe5ede11c, 0xb13c7a47, 
	0xdf599cd2, 0x733f55f2, 0xce791814, 0x37bf73c7, 0xcdea53f7, 0xaa5b5ffd, 0x6f14df3d, 0xdb867844, 
	0xf381caaf, 0xc43eb968, 0x342c3824, 0x405fc2a3, 0xc372161d, 0x250cbce2, 0x498b283c, 0x9541ff0d, 
	0x017139a8, 0xb3de080c, 0xe49cd8b4, 0xc1906456, 0x84617bcb, 0xb670d532, 0x5c74486c, 0x5742d0b8};
    return de2[num];
}
int getDe3(int num){
    int de3[256] =   {
    0xf4a75051, 0x4165537e, 0x17a4c31a, 0x275e963a, 0xab6bcb3b, 0x9d45f11f, 0xfa58abac, 0xe303934b, 
	0x30fa5520, 0x766df6ad, 0xcc769188, 0x024c25f5, 0xe5d7fc4f, 0x2acbd7c5, 0x35448026, 0x62a38fb5, 
	0xb15a49de, 0xba1b6725, 0xea0e9845, 0xfec0e15d, 0x2f7502c3, 0x4cf01281, 0x4697a38d, 0xd3f9c66b, 
	0x8f5fe703, 0x929c9515, 0x6d7aebbf, 0x5259da95, 0xbe832dd4, 0x7421d358, 0xe0692949, 0xc9c8448e, 
	0xc2896a75, 0x8e7978f4, 0x583e6b99, 0xb971dd27, 0xe14fb6be, 0x88ad17f0, 0x20ac66c9, 0xce3ab47d, 
	0xdf4a1863, 0x1a3182e5, 0x51336097, 0x537f4562, 0x6477e0b1, 0x6bae84bb, 0x81a01cfe, 0x082b94f9, 
	0x48685870, 0x45fd198f, 0xde6c8794, 0x7bf8b752, 0x73d323ab, 0x4b02e272, 0x1f8f57e3, 0x55ab2a66, 
	0xeb2807b2, 0xb5c2032f, 0xc57b9a86, 0x3708a5d3, 0x2887f230, 0xbfa5b223, 0x036aba02, 0x16825ced, 
	0xcf1c2b8a, 0x79b492a7, 0x07f2f0f3, 0x69e2a14e, 0xdaf4cd65, 0x05bed506, 0x34621fd1, 0xa6fe8ac4, 
	0x2e539d34, 0xf355a0a2, 0x8ae13205, 0xf6eb75a4, 0x83ec390b, 0x60efaa40, 0x719f065e, 0x6e1051bd, 
	0x218af93e, 0xdd063d96, 0x3e05aedd, 0xe6bd464d, 0x548db591, 0xc45d0571, 0x06d46f04, 0x5015ff60, 
	0x98fb2419, 0xbde997d6, 0x4043cc89, 0xd99e7767, 0xe842bdb0, 0x898b8807, 0x195b38e7, 0xc8eedb79, 
	0x7c0a47a1, 0x420fe97c, 0x841ec9f8, 0x00000000, 0x80868309, 0x2bed4832, 0x1170ac1e, 0x5a724e6c, 
	0x0efffbfd, 0x8538560f, 0xaed51e3d, 0x2d392736, 0x0fd9640a, 0x5ca62168, 0x5b54d19b, 0x362e3a24, 
	0x0a67b10c, 0x57e70f93, 0xee96d2b4, 0x9b919e1b, 0xc0c54f80, 0xdc20a261, 0x774b695a, 0x121a161c, 
	0x93ba0ae2, 0xa02ae5c0, 0x22e0433c, 0x1b171d12, 0x090d0b0e, 0x8bc7adf2, 0xb6a8b92d, 0x1ea9c814, 
	0xf1198557, 0x75074caf, 0x99ddbbee, 0x7f60fda3, 0x01269ff7, 0x72f5bc5c, 0x663bc544, 0xfb7e345b, 
	0x4329768b, 0x23c6dccb, 0xedfc68b6, 0xe4f163b8, 0x31dccad7, 0x63851042, 0x97224013, 0xc6112084, 
	0x4a247d85, 0xbb3df8d2, 0xf93211ae, 0x29a16dc7, 0x9e2f4b1d, 0xb230f3dc, 0x8652ec0d, 0xc1e3d077, 
	0xb3166c2b, 0x70b999a9, 0x9448fa11, 0xe9642247, 0xfc8cc4a8, 0xf03f1aa0, 0x7d2cd856, 0x3390ef22, 
	0x494ec787, 0x38d1c1d9, 0xcaa2fe8c, 0xd40b3698, 0xf581cfa6, 0x7ade28a5, 0xb78e26da, 0xadbfa43f, 
	0x3a9de42c, 0x78920d50, 0x5fcc9b6a, 0x7e466254, 0x8d13c2f6, 0xd8b8e890, 0x39f75e2e, 0xc3aff582, 
	0x5d80be9f, 0xd0937c69, 0xd52da96f, 0x2512b3cf, 0xac993bc8, 0x187da710, 0x9c636ee8, 0x3bbb7bdb, 
	0x267809cd, 0x5918f46e, 0x9ab701ec, 0x4f9aa883, 0x956e65e6, 0xffe67eaa, 0xbccf0821, 0x15e8e6ef, 
	0xe79bd9ba, 0x6f36ce4a, 0x9f09d4ea, 0xb07cd629, 0xa4b2af31, 0x3f23312a, 0xa59430c6, 0xa266c035, 
	0x4ebc3774, 0x82caa6fc, 0x90d0b0e0, 0xa7d81533, 0x04984af1, 0xecdaf741, 0xcd500e7f, 0x91f62f17, 
	0x4dd68d76, 0xefb04d43, 0xaa4d54cc, 0x9604dfe4, 0xd1b5e39e, 0x6a881b4c, 0x2c1fb8c1, 0x65517f46, 
	0x5eea049d, 0x8c355d01, 0x877473fa, 0x0b412efb, 0x671d5ab3, 0xdbd25292, 0x105633e9, 0xd647136d, 
	0xd7618c9a, 0xa10c7a37, 0xf8148e59, 0x133c89eb, 0xa927eece, 0x61c935b7, 0x1ce5ede1, 0x47b13c7a, 
	0xd2df599c, 0xf2733f55, 0x14ce7918, 0xc737bf73, 0xf7cdea53, 0xfdaa5b5f, 0x3d6f14df, 0x44db8678, 
	0xaff381ca, 0x68c43eb9, 0x24342c38, 0xa3405fc2, 0x1dc37216, 0xe2250cbc, 0x3c498b28, 0x0d9541ff, 
	0xa8017139, 0x0cb3de08, 0xb4e49cd8, 0x56c19064, 0xcb84617b, 0x32b670d5, 0x6c5c7448, 0xb85742d0};
    return de3[num];
}

