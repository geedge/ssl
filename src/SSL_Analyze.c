/*
 * SSL_Analyze.c
 *
 *  Created on: 2013-5-2
 *      Author: lis
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <dlfcn.h>
#include "SSL_Analyze.h"
#include "SSL_Message.h"
#include "ssl.h"
#include <MESA/MESA_prof_load.h>
#include "SSL_Proc.h"


#define GIT_VERSION_CATTER(v) __attribute__((__used__)) const char * GIT_VERSION_##v = NULL
#define GIT_VERSION_EXPEND(v) GIT_VERSION_CATTER(v)

#ifdef __cplusplus
extern "C"
{
#endif

    /* VERSION TAG */
#ifdef GIT_VERSION
    GIT_VERSION_EXPEND(GIT_VERSION);
#else
    static __attribute__((__used__)) const char * GIT_VERSION_UNKNOWN = NULL;
#endif
#undef GIT_VERSION_CATTER
#undef GIT_VERSION_EXPEND

#ifdef __cplusplus
}
#endif

struct ssl_runtime_para g_ssl_runtime_para;

int ssl_read_config(const char* filename)
{
	FILE *fp=NULL;
	if(((fp = fopen(filename, "r"))!=NULL))
	{
		char 	buf[2048]={0};	
		int 	region_id=0;
		char 	region_name[REGION_NAME_LEN]={0};	
		 while( fgets(buf, sizeof(buf), fp))
		 {
			 int temp = sscanf(buf, "%d\t%31s", &region_id, region_name);  //szieof(region_name)=32
			 if ( 2 > temp )
			 {
				 printf( "ssl.so : ssl.conf %s read error\n", filename);
				 return -1;
			 }
			 if(region_id>=MAX_REGION_NUM)
			 {
			 	 printf( "ssl.so : ssl.conf %d bigger than MAX_REGION_NUM\n", region_id);
				 return -1;
			 }
			 memcpy(g_ssl_runtime_para.ssl_conf_regionname[region_id], region_name, strlen(region_name));
			 g_ssl_runtime_para.ssl_region_cnt++;
			 memset(region_name, 0, sizeof(region_name));
		}
		fclose(fp);
	}
	else  
	{
		 printf( "ssl.so : ssl.conf %s open error\n", filename);
		 return -1;
	}
	return 0;
}

int ssl_add_proto_tag(const struct streaminfo *a_stream, const char* value, int len)
{
	struct ssl_proto_tag* proto_tag = (struct ssl_proto_tag*)project_req_get_struct(a_stream, g_ssl_runtime_para.proto_tag_id);
	if(proto_tag == NULL)   
	{        
		proto_tag = (struct ssl_proto_tag *)dictator_malloc(a_stream->threadnum, sizeof(struct ssl_proto_tag)); 
		memcpy(proto_tag->buf, value, len);  
		proto_tag->buf[len]='\0';
	
		if(0 != project_req_add_struct((struct streaminfo *)a_stream,  g_ssl_runtime_para.proto_tag_id, proto_tag))        
		{            
			dictator_free(a_stream->threadnum, proto_tag);
			proto_tag=NULL;
			return -1;        
		}    
	} 

	return 0;
}

void ssl_proto_tag_free(int thread_seq, void *value)
{
	if(value!=NULL)
	{
		dictator_free(thread_seq, value);
		value=NULL;
	}
	
	return;
}

int ssl_init_context(void **pme, int thread_seq)
{
	if(NULL!=*pme)
	{
		return -1;
	}

	struct ssl_runtime_context *ssl_context = (struct ssl_runtime_context *)dictator_malloc(thread_seq, sizeof(struct ssl_runtime_context));
	memset(ssl_context, 0, sizeof(struct ssl_runtime_context));

	ssl_context->link_state=SSL_FLASE;
	ssl_context->over_flag=SSL_FLASE;
	ssl_context->is_ssl_stream=SSL_FLASE;
	ssl_context->version=UNKNOWN_VERSION;
	ssl_context->business.return_value=PROT_STATE_GIVEME; 
	
	*pme = (void*)ssl_context;
	return 0;
}

void ssl_release_context(struct ssl_runtime_context *ssl_context, int thread_seq)
{
	if(NULL==ssl_context)
	{
		return;
	}

	if(ssl_context->record.cache_buff!=NULL)
	{
		dictator_free(thread_seq, ssl_context->record.cache_buff);
	}
		
	dictator_free(thread_seq, ssl_context);
	ssl_context=NULL;
}

extern "C" char SSL_ENTRY(const struct streaminfo *a_tcp, void**pme, int thread_seq, const void *a_packet)
{
	int return_val=0;
	char state=APP_STATE_GIVEME;
	struct ssl_runtime_context *ssl_context=(struct ssl_runtime_context *)(*pme);

	switch(a_tcp->opstate)
	{
		case OP_STATE_PENDING:
			if(g_ssl_runtime_para.ssl_interested_region_flag < SSL_KEY)
			{
				return APP_STATE_DROPME;
			}
			
			ssl_init_context(pme,thread_seq);
			ssl_context=(struct ssl_runtime_context *)(*pme);
		case OP_STATE_DATA:
			return_val=ssl_parse_stream(a_tcp, ssl_context ,thread_seq, a_packet);
			break;
		case OP_STATE_CLOSE:
			if(ssl_context->version!=UNKNOWN_VERSION)
			{
				ssl_add_proto_tag( a_tcp, "SSL", strlen("SSL"));
			}

			return_val=ssl_parse_stream(a_tcp, ssl_context ,thread_seq, a_packet);	
			break;
		default:
			break;
	}

	if(SSL_FLASE==return_val)
	{
		state=APP_STATE_DROPME;
	}

	if(ssl_context->business.return_value&PROT_STATE_DROPPKT)
	{
		state|=APP_STATE_DROPPKT;
	}

	if(state&APP_STATE_DROPME || a_tcp->opstate==OP_STATE_CLOSE)
	{
		if(ssl_context->is_call_business==1)
		{
			ssl_context->over_flag=1;
			ssl_call_plugins(a_tcp, ssl_context, NULL, 0, SSL_INTEREST_KEY_MASK, thread_seq, a_packet);
		}
		
		ssl_release_context(ssl_context, thread_seq);
		*pme=NULL;
	}
	else
	{
		ssl_context->business.return_value=0;
	}
	
	return state;
}

extern "C" int SSL_INIT(void)
{
	memset(&g_ssl_runtime_para, 0, sizeof(struct ssl_runtime_para));

	if(ssl_read_config("./conf/ssl/ssl.conf")!=0)
	{
		return -1;
	}

	const char *filename="./conf/ssl/ssl_main.conf";
	MESA_load_profile_int_def(filename, "SSL", "MAX_CACHE_LEN", &g_ssl_runtime_para.max_cache_len, 10240);
	MESA_load_profile_int_def(filename, "SSL", "PARSE_CERTIFICATE_DETAIL", &g_ssl_runtime_para.parse_certificate_detail, 1);

	ssl_ja3_init();
	g_ssl_runtime_para.proto_tag_id=project_producer_register("MESA_PROTO", "struct", ssl_proto_tag_free);

	return 0;
}

extern "C" void SSL_DESTROY(void)
{
	return;
}

extern "C" void SSL_GETPLUGID(unsigned short plugid)
{
	g_ssl_runtime_para.ssl_plugid = plugid;
}

extern "C" void SSL_PROT_FUNSTAT(unsigned long long protflag)
{
	if(0==protflag)
	{
		return;
	}
	
	g_ssl_runtime_para.ssl_interested_region_flag=protflag;

	return;
}

unsigned long long ssl_getRegionID(char *string, int str_len, const char g_string[MAX_REGION_NUM][REGION_NAME_LEN])
{
	unsigned long long i=0;
	for(i=0;i<g_ssl_runtime_para.ssl_region_cnt;i++)
	{		
		if(0==strcasecmp(g_string[i], string))
		{
			return i;
		}
	}
	return 0;
}

extern "C" long long SSL_FLAG_CHANGE(char* flag_str)
{
	if(flag_str==NULL) return -1;
	
	long long protflag = 0;
	char *start_token = flag_str;
	char *end_token = flag_str;
	char *end_pos = flag_str+strlen(flag_str);
	char region_name[REGION_NAME_LEN] = {0};
	
	while (end_token < end_pos)
	{		
		end_token = (char*)memchr(start_token, ',', end_pos-start_token);
		if(end_token!=NULL)
		{
			memcpy(region_name, start_token, end_token-start_token);
			start_token = end_token+1;
			end_token += 1;
		}
		else 
		{
			memcpy(region_name, start_token, end_pos-start_token);
			end_token = end_pos;
		}
		long long region_id = ssl_getRegionID(region_name, strlen(region_name), g_ssl_runtime_para.ssl_conf_regionname);
		if(-1==region_id)
		{
			printf( "ssl.so : PROT_CHANGE %s read %s error\n", flag_str, region_name);
			return -1;
		}
		protflag |= ((long long)1)<<region_id;
		memset(region_name, 0, REGION_NAME_LEN);
	}	
	return protflag;
}

