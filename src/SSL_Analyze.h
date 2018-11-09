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

#define SSL_RETURN_NORM 				0x53
#define SSL_RETURN_UNNORM 				0x54
#define SSL_RETURN_RESET_BUFFER			0x55
#define SSL_RETURN_DROPME 				0x57

#define MAX_REGION_NUM 15
#define REGION_NAME_LEN 32

typedef struct ssl_prog_runtime_parameter_t
{ 	
	unsigned long long 	ssl_interested_region_flag;
	unsigned long long 	ssl_region_cnt;
	char 				ssl_conf_filename[256];	
	unsigned short 		ssl_plugid;
	char 				ssl_conf_regionname[MAX_REGION_NUM][REGION_NAME_LEN];	
}ssl_prog_runtime_parameter_t;


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
