#include <openssl/ripemd.h>
#include <cstdio>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <cstring>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <cstdio>
#include <unistd.h>

#include "tools.h"
#include "queue.h"

#define VER 33
#define CON_NUM 5

using namespace std;

const char* text1 = "Hello, B";
const char* text3 = "Hello, A";
const char* text2 = text1;
const char* text4 = text3;

static int padding = RSA_PKCS1_PADDING;

void hash20Bytes(unsigned char* str, int size, unsigned char* result)
{
	RIPEMD160(str, size, result);
}

static void printLastError(char *msg)
{
        char* err = (char*)malloc(130);
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        printf("%s ERROR: %s\n", msg, err);
        free(err);
}

static int keyGenerate(const char* pub_name, const char* pri_name)
{
        int ret = 0;
        RSA *r = NULL;
        BIGNUM *bne = NULL;
        BIO *bp_public = NULL, *bp_private = NULL;
        int bits = 2048;
        unsigned long e = RSA_F4;

        bne = BN_new();
        ret = BN_set_word(bne, e);
        if (ret != 1)
        {
                goto freeall;
        }

        r = RSA_new();
        ret = RSA_generate_key_ex(r, bits, bne, NULL);
        if (ret != 1)
        {
                  goto freeall;
        }

        bp_public = BIO_new_file(pub_name, "w+");
        ret = PEM_write_bio_RSAPublicKey(bp_public, r);
        if(ret != 1)
        {
                goto freeall;
        }

        bp_private = BIO_new_file(pri_name, "w+");
        ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);

freeall:
        BIO_free_all(bp_public);
        BIO_free_all(bp_private);
        RSA_free(r);
        BN_free(bne);

        return ret == 1;
}

int getKey(const char* pub_name, char* public_key)
{
        int size;
        FILE* fp = fopen(pub_name, "r");
        if(!fp)
        {
                exit(0);
        }

        fseek(fp, 0, SEEK_END);
        size = ftell(fp);
        fseek(fp, 0, SEEK_SET); 
        fread(public_key, size, 1, fp);
        fclose(fp);
}

static RSA* createRSA(unsigned char* key, int pub)
{
	RSA* rsa = NULL;
	BIO* keybio ;
	keybio = BIO_new_mem_buf(key, -1);
	if (!keybio)
	{
		printf("Failed to create key BIO");
		return 0;
	}
	if (pub)
	{
		rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	}
	else
	{
		rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	}
	if (!rsa)
	{
		printLastError((char*)"Failed to create RSA");
		//printf( "Failed to create RSA");
	}

	return rsa;
}

int public_encrypt(unsigned char *data, int data_len, unsigned char *key, unsigned char *encrypted)
{
	RSA* rsa = createRSA(key, 1);
	int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
	return result;
}

int private_decrypt(unsigned char *enc_data, int data_len, unsigned char *key, unsigned char *decrypted)
{
	RSA* rsa = createRSA(key, 0);
	int result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
	return result;
}

int private_encrypt(unsigned char *data, int data_len, unsigned char *key, unsigned char *encrypted)
{
	RSA* rsa = createRSA(key, 0);
	int result = RSA_private_encrypt(data_len, data, encrypted, rsa, padding);
	return result;
}

int public_decrypt(unsigned char *enc_data, int data_len, unsigned char *key, unsigned char *decrypted)
{
	RSA* rsa = createRSA(key, 1);
	int result = RSA_public_decrypt(data_len, enc_data, decrypted, rsa, padding);
	return result;
}

void print(char* ar)
{
        for (int i = 0; ar[i] != '\0'; ++i)
                printf("%c", ar[i]);
        printf("\n");
}

static void pushIn(char *dest, int position, char *source, int num)
{
	memcpy(&(dest[position]), source, num);
}

int toSign(unsigned char *data, int data_len, unsigned char *result)
{
	unsigned char private_key[4096];
	unsigned char hash[20];

	hash20Bytes(data, data_len, hash);

	memset(private_key, '\0', 4096);
	getKey("private.pem", (char*)private_key);

	int encrypted_length;

	encrypted_length = private_encrypt(hash, 20, private_key, result);
	
	return encrypted_length;
}

static bool eqStr(unsigned char *str1, unsigned char *str2, int size)
{
	for (int i = 0; i < size; ++i)
		if (str1[i] != str2[i])
		{
			printf("%d\n", i);
			return false;
		}
	return true;
}

bool checkSign(unsigned char *data, int data_len, unsigned char *signature, int sig_len)
{
	unsigned char public_key[4096];
	unsigned char hash[20];
	
	hash20Bytes(data, data_len, hash);
	
	memset(public_key, '\0', 4096);
	getKey("public.pem", (char*)public_key);
	
	unsigned char decrypted[20];
	int decrypted_length;

	decrypted_length = public_decrypt(signature, sig_len, public_key, decrypted);

	return eqStr(hash, decrypted, 20);
}

static void createTransactionStr(char num, pid_type pid, char *result)
{
	result[0] = num;
	result[1] = '\0';
	pushIn(result, sizeof(num), pid.str, sizeof(pid));
}

int createAuthorizationString(char num, pid_type pid, char *text1, char *text2, unsigned char *result)
{
	createTransactionStr(num, pid, (char*)result);
	int tmp_size = sizeof(num) + sizeof(pid);
	int len2 = strlen(text2);
	pushIn((char*)result, tmp_size, text1, strlen(text1));

	unsigned char signature[4096];
	int sign_size = toSign(result, tmp_size + strlen(text1), signature);

	pushIn((char*)result, tmp_size, text2, len2);
	tmp_size += len2;
	pushIn((char*)result, tmp_size, (char*)signature, sign_size);

	return tmp_size + sign_size;
}

//Authorization::num = 0;

Connection::Connection(bool m, MsgQueue& q)
{
	my_pid.num = getpid();
	q.send((int)m + 1, my_pid.str, 4);
	q.recieve((int)(!m) + 1, partners_pid.str);
}

Authorization::Authorization(bool m) : queue(VER), master(m), num(1)
{
	con = Connection(m, queue);	
}

void Authorization::authorizate()
{
	char str[4096];
	int len;
	len = createAuthorizationString(num++, con.getPartnersPid(), (char*)text1, (char*)text2, (unsigned char*)str);
	queue.send((int)master + CON_NUM, str, len);
	
	/*char tmp[4096];
	queue.recieve((int)(!master) + CON_NUM, tmp);
	if (eqStr((unsigned char*)str, (unsigned char*)tmp, len))
		printf("Eq\n");
	else
		printf("Uneq\n");
	printf("\n");
	for (int i = 0; i < len; printf("%d", (int)str[i++]));
	printf("\n");*/
}

bool Authorization::check()
{
	char str[4096];
	int len;
	len = queue.recieve((int)(!master) + CON_NUM, str);

	/*queue.send((int)(master) + CON_NUM, str, len);
	printf("\n");
	for (int i = 0; i < len; printf("%d", (int)str[i++]));
	printf("\n");*/

	char tmp[100];
	int size = sizeof(num) + sizeof(con.getMyPid());

	if (str[0] != num++ || !eqStr((unsigned char*)con.getMyPid().str, (unsigned char*)&(str[sizeof(num)]), sizeof(pid_type)))
	{
		printf("Wrong partner\n");
		return false;
	}

	memcpy(tmp, str, size);
	int t1_size = strlen(text1);
	pushIn(tmp, size, (char*)text1, t1_size);

	int tmp_len = size + strlen((char*)text2);

	return checkSign((unsigned char*)tmp, t1_size + size, (unsigned char*)&(str[tmp_len]), len - tmp_len);
}

struct MsgStruct
{
        long int message_type;
        int size;
        char data[25];
};


MsgQueue::MsgQueue(int version)
{	
        key_t key = ftok("tools.h", version);

        if ((id = msgget(key, IPC_CREAT | 0666)) == -1)
	{
        	perror("msgget error");
               	exit(-1);
	}
}

void MsgQueue::send(long type, char* data, int size)
{
	message_send(id, type, data, size);
}

int MsgQueue::recieve(long type, char *res)
{
	return message_recieve(id, type, res);
}

pid_type Connection::getMyPid()
{
	return my_pid;
}

pid_type Connection::getPartnersPid()
{
        return partners_pid;
}
