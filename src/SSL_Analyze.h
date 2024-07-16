#pragma once

#include <MESA/stream.h>

#include "ssl.h"
#include "SSL_Message.h"

#if(__GNUC__ * 100 + __GNUC_MINOR__ * 10 + __GNUC_PATCHLEVEL__ >= 410)
#define atomic_inc(x) __sync_add_and_fetch((x),1)
#define atomic_dec(x) __sync_sub_and_fetch((x),1)
#define atomic_add(x,y) __sync_add_and_fetch((x),(y))
#define atomic_sub(x,y) __sync_sub_and_fetch((x),(y))
typedef long atomic_t;
#define ATOMIC_INIT(i)  { (i) }
#define atomic_read(x) __sync_add_and_fetch((x),0)
#define atomic_set(x,y) __sync_lock_test_and_set((x),y)
#else 
typedef long atomic_t;
#define atomic_inc(x)	((*(x))++)
#define atomic_dec(x)	((*(x))--)
#define atomic_add(x,y) ((*(x))+=(y))
#define atomic_sub(x,y) ((*(x))-=(y))
#define ATOMIC_INIT(i)  { (i) }
#define atomic_read(x) 	(*(x))
#define atomic_set(x,y)	((*(x))=(y))
#endif 

#define SSL_RETURN_NORM 				0x53
#define SSL_RETURN_UNNORM 				0x54
#define SSL_RETURN_GIVEME 				0x56
#define SSL_RETURN_DROPME 				0x57

#define MAX_REGION_NUM 					15
#define REGION_NAME_LEN 				32

#define SSL_KEY 								3
#define SSL_TRUE 								1
#define SSL_FLASE 								0
struct ssl_proto_tag
{
	char buf[8];
};


#define SSL_FRAG_CHELLO_BRIDEGE_NAME "SSL_FRAG_CHELLO_BRIDGE"
#define MAX_DETAIN_FRAG_CHELLO_NUM 8
struct frag_chello
{
	struct detain_pkt *p[MAX_DETAIN_FRAG_CHELLO_NUM];
	unsigned int p_sz;
	unsigned int finish;
};


enum fs_metric
{
	FS_METRIC_DETAIN_FRAG_CHELLO_NUM = 0,
	FS_METRIC_DETAIN_FRAG_CHELLO_FORWARD,
	FS_METRIC_DETAIN_FRAG_CHELLO_FREE,
	FS_METRIC_DETAIN_FRAG_CHELLO_SESSION,
	FS_METRIC_DETAIN_FRAG_CHELLO_FINISH,
	FS_METRIC_DETAIN_FRAG_CHELLO_TIMEOUT,
	FS_METRIC_MAX
};

struct ssl_runtime_para
{ 	
	unsigned long long 	ssl_interested_region_flag;
	unsigned long long 	ssl_region_cnt;
	unsigned short ssl_plugid;
	char ssl_conf_regionname[MAX_REGION_NUM][REGION_NAME_LEN];
	char stat_filename[256];
	char stat_appname[16];
	int proto_tag_id ;
	int max_cache_len;
	int parse_certificate_detail;
	unsigned int detain_frag_chello_num;
	int frag_chello_exdata_idx;
	struct fieldstat_easy *fs;
	int fs_metric_id[FS_METRIC_MAX];
};

struct ssl_business_info
{
	void* param;
	unsigned char return_value;
};

struct ssl_record_trunk
{
	unsigned char is_offset_header;
	struct ssl_record_header header;
	int cache_len;
	char* cache_buff;
};

struct ssl_runtime_context
{
	unsigned char link_state;
	unsigned char over_flag;
	unsigned char is_ssl_stream;
	unsigned char first_pkt_flag;
	unsigned char is_call_business;
	unsigned char padding;
	unsigned short version; //SSL versions, definition like TLSV1_2_VERSION in ssl.h
	struct ssl_stream stream;
	struct ssl_record_trunk record;
	struct ssl_business_info business;
};

extern struct ssl_runtime_para g_ssl_runtime_para;

int ssl_ja3_init(void);

