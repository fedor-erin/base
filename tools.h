#ifndef __ToOlS__
#define __ToOlS__

typedef union
{
        int num;
        char str[4];
} pid_type;

class MsgQueue
{
        int id;  
public:
        MsgQueue(int version);
        void send(long type, char* data, int size);
	int recieve(long type, char *res);
};

class Connection
{
	pid_type my_pid, partners_pid;
public:
	Connection(bool m, MsgQueue &q);
	Connection(){}
	pid_type getMyPid();
	pid_type getPartnersPid();
};

class Authorization
{
	MsgQueue queue;
	Connection con;
	bool master;
	char num;
public:

	Authorization(bool m);
	void authorizate();
	bool check();
};

void hash20Bytes(unsigned char* str, int size, unsigned char* result);

int getKey(const char* pub_name, char* public_key);

int public_encrypt(unsigned char *data, int data_len, unsigned char *key, unsigned char *encrypted);

int private_decrypt(unsigned char *enc_data, int data_len, unsigned char *key, unsigned char *decrypted);

int private_encrypt(unsigned char *data, int data_len, unsigned char *key, unsigned char *encrypted);

int public_decrypt(unsigned char *enc_data, int data_len, unsigned char *key, unsigned char *decrypted);

void print(char* ar);

void makeTransactionStr(char num, pid_type pid, char *result);

int toSign(unsigned char *data, int data_len, unsigned char *result);

bool checkSign(unsigned char *data, int data_len, unsigned char *signature, int sid_len);

#endif
