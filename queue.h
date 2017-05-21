#ifndef __QUEUE_H__
#define __QUEUE_H__

#ifdef __cplusplus
extern "C" {
#endif

extern void message_send(int id, long type, char* data, int size);

extern int message_recieve(int id, long type, char* res);

#ifdef __cplusplus
}
#endif

#endif
