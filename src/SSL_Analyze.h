/*
 * SSL_Analyze.h
 *
 *  Created on: 2013-5-2
 *      Author: lis
 */

#ifndef SSL_ANALYZE_H_
#define SSL_ANALYZE_H_

#define	MESA_INCLUDE				1

#if MESA_INCLUDE
#include <MESA/stream.h>
#else
#include "stream.h"
#endif

#include "ssl.h"

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
#define SSL_RETURN_RESET_BUFFER			0x55
#define SSL_RETURN_GIVEME 				0x56
#define SSL_RETURN_DROPME 				0x57

#define MAX_REGION_NUM 					15
#define REGION_NAME_LEN 				32

enum fs_metric
{
	SSL_STAT_PKTS_C2S = 0,
	SSL_STAT_PKTS_S2C,
	SSL_STAT_BITS_C2S,
	SSL_STAT_BITS_S2C,
	FS_METRIC_DETAIN_FRAG_CHELLO_NUM,
	FS_METRIC_DETAIN_FRAG_CHELLO_FORWARD,
	FS_METRIC_DETAIN_FRAG_CHELLO_FREE,
	FS_METRIC_DETAIN_FRAG_CHELLO_SESSION,
	FS_METRIC_DETAIN_FRAG_CHELLO_FINISH,
	FS_METRIC_DETAIN_FRAG_CHELLO_TIMEOUT,
	FS_METRIC_MAX
};


typedef struct ssl_prog_runtime_parameter_t
{ 	
	unsigned long long 	ssl_interested_region_flag;
	unsigned long long 	ssl_region_cnt;
	char 				ssl_conf_filename[256];	
	unsigned short 		ssl_plugid;
	char 				ssl_conf_regionname[MAX_REGION_NUM][REGION_NAME_LEN];		
	void*				stat_handler;
	int 				stat_screen_print_trigger;
	int 				stat_cycle;		
	int 				ssl_switch_no_biz;
	
	int					stat_field[FS_METRIC_MAX];	
	int                 stat_dst_port;
	uint64_t			stat_value[FS_METRIC_MAX];	
	char 				stat_filename[256];
	char                stat_dst_ip[64];
	char                stat_appname[16];
	
	int					proto_tag_id ;

	unsigned int detain_frag_chello_num;
	int frag_chello_exdata_idx;

}ssl_prog_runtime_parameter_t;

struct ssl_proto_tag_t
{    
	char buf[8];
};

#define SSL_FRAG_CHELLO_BRIDEGE_NAME "SSL_FRAG_CHELLO_BRIDGE"
struct frag_chello_internal
{
	struct ssl_frag_chello frag_chello;
	unsigned int finish;
};


#ifdef __cplusplus
extern "C" {
#endif

int 				SSL_INIT(void);
char 			SSL_ENTRY(struct streaminfo *a_tcp, void**pme, int thread_seq, void *a_pcaket);
void 			SSL_DESTROY(void);
void 			SSL_GETPLUGID(unsigned short plugid);
void 			SSL_PROT_FUNSTAT(unsigned long long protflag);
long long 		SSL_FLAG_CHANGE(char* flag_str);
void ssl_initStructClientHello(st_client_hello_t* pstClientHello);
void ssl_initStructServerHello(st_server_hello_t* pstServerHello);


#ifdef __cplusplus
}
#endif
#endif /* SSL_ANALYZE_H_ */
