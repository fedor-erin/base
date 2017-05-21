#include <sys/msg.h>
#include <sys/ipc.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

#include "queue.h"

struct Data
{
	int size;
	char data[25];
};

struct MsgStruct
{
        long int message_type;
        struct Data msg;
};

void message_send(int id, long type, char* data, int size)
{
	struct MsgStruct msg;
	int i;
        msg.message_type = type;

        for (i = 0; i < size; i += 20)
        {
                memcpy(msg.msg.data, &(data[i]), (i + 20 > size) ? size % 20 : 20);
                msg.msg.size = (i + 20 > size) ? size % 20 : 20;

                if (msgsnd(id, &msg, sizeof(struct Data), 0))
                {
                        perror("Send error");
                        exit(-1);
                }
        }

        if (!(size % 20))
        {
                msg.msg.size = 0;
                if (msgsnd(id, &msg, sizeof(struct Data), 0))
                {
                        perror("Send error");
                        exit(-1);
                }
        }
}

int message_recieve(int id, long type, char* res)
{
        struct MsgStruct msg;
        int size = 0;
        msg.msg.size = 20;

        for (; msg.msg.size == 20; size += msg.msg.size)
        {
                if ((msgrcv(id, &msg, sizeof(struct Data), type, 0)) == -1)
                {
                        perror("Recieve error");
                        exit(-1);
                }
                if (msg.msg.size)
                        memcpy(&(res[size]), msg.msg.data, msg.msg.size);
        }
        return size;
}

