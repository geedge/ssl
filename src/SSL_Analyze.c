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
#include "SSL_Proc.h"
#include "field_stat2.h"
#include "MESA_prof_load.h"


ssl_prog_runtime_parameter_t 	g_ssl_prog_para;

int SSL_VERSION_1_20200617 = 0;

void ssl_history()
{
//2014-03-03 V0.1 parse ssl, include expand ;
//2014-03-03 V0.1 modify service back_state, DROPME return DROPME ;
//2014-03-03 V0.1 server_name add length judge;
//2014-03-04 V0.1 use for youtube only analyse server_name, close certificate
//2014-03-30 V0.1 xjfd
//2014-03-31 V0.1 review ssl code after xj online , complete ssl recognition and parse
//2014-04-03 V0.1 iUnAnalyseLen bug
//2014-04-04 V0.1 write log, use define control write log or not 
//2014-04-04 V0.1 bug1 : unanlyzelen< is pcaket trunk ; bug2 : clean cert before analeze_cert
//2014-04-04 V0.1 one stream , not half stream
//2014-04-10 V0.1 server_name_type 0000 or 0008 two bytes ,cert: ilength become int
//2014-05-15 V0.1 newplatform
//2014-05-15 V0.1 ssl conf modify 
//2014-05-29 V0.1 while unsigned int bug and fcloe(fp) and free(output) and close printf
//2014-06-03 V0.1 review code , check unsigned int and int and return_value
//2014-06-05 V0.1 malformation ssl certificate
//2014-10-08 V0.1 version 0303
//2014-10-31 V0.1 newplatform
//2014-11-18 V0.1 delete KILLME; certificate and certificate_detail can get by biz plugin at the same time. ssl_message.h->ssl.h
//2014-11-20 V0.1 subbak
//2014-11-21 V0.1 memcheck clientHello
//2014-11-28 V0.1 ssl.h  and SSL_Message.h
//2015-01-06 V0.1 new plugin
//2015-01-27 V0.1 add "if(a_ssl_stream->stSSLCert->totallen<0)  return SSL_RETURN_DROPME;"
//2015-03-23 V0.1 Conditional jump or move depends on uninitialised value
//2015-10-29 V0.1 such as ftp smtp
//2015-12-23 V0.1 cert level
//2015-12-31 V0.1 lost prco, buf, and pcSslBuffer malloc if need, and clienthello...
//2016-08-08 V0.2 cert issuer pport O C CN field and uiMaxBuffLen=0
//2016-09-06 V0.2 1. server hello : method_len=1 2.  2. add version info
//2016-09-10 V0.2 1. ssl_read_specific_cert and ssl_read_all_cert
//2016-09-28 V0.2 pstClientServerName dictator_malloc 
//2016-11-10 V0.2 clientHello Callback 
//2017-03-08 V0.2 CERT Sub
//2017-04-15 V0.2 session->buf=cert when cert detail
//2017-04-19 V0.2 cert detail
//2018-06-29 V0.2 cert extension
//2018-07-30 V0.2 APPLICATION_DATA bug
//2018-11-08 V0.2 multi-san
//2018-11-29 V0.2 san dictator_malloc
//2018-12-04 V0.2 openssl parse certificate bug
//2018-12-07 V0.2 certificate maxnum; memcheck
//2019-01-28 V0.2 1. bug update: memset in cert 2. ssl cert_chain:FF FF
//2019-12-20 V0.2 add info statistics
//2020-01-09 V0.2 add stream tag
//2020-06-15 V0.2 memset buf 
//2020-06-17 V0.2 increase MAX_DATA_BUFFER 40960 


//to do 
//certificate ANSL 

}

int ssl_readconf(const char* filename)
{	
	FILE 	*fp 			= NULL;
	char 	buf[2048] 		= {0};	
	int 	region_id 		= 0;
	int 	temp 		= 0;
	char 	region_name[REGION_NAME_LEN] 	= {0};	

	if(((fp = fopen(filename, "r"))!=NULL))
	{
		 while( fgets(buf, sizeof(buf), fp))
		 {
			 temp = sscanf(buf, "%d\t%s", &region_id, region_name);
			 if ( 2 > temp )
			 {
				 printf( "ssl.so : ssl.conf %s read error\n", filename);
				 return -1;
			 }
			 if(region_id>MAX_REGION_NUM)
			 {
			 	 printf( "ssl.so : ssl.conf %d bigger than MAX_REGION_NUM\n", region_id);
				 return -1;
			 }
			 strncpy(g_ssl_prog_para.ssl_conf_regionname[region_id], region_name, strlen(region_name));
			 g_ssl_prog_para.ssl_region_cnt++;
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

int ssl_readMainConf(const char* filename)
{
	char 	http_log_filename[256];	
	
	
	MESA_load_profile_int_def(filename, "FUNCTION", "stat_screen_print", &g_ssl_prog_para.stat_screen_print_trigger,0);
	MESA_load_profile_int_def(filename, "FUNCTION", "stat_cycle", &g_ssl_prog_para.stat_cycle,0);
	MESA_load_profile_string_def(filename, "FUNCTION", "stat_file", g_ssl_prog_para.stat_filename, sizeof(g_ssl_prog_para.stat_filename),"./log/ssl/ssl_stat.log");
	MESA_load_profile_short_def(filename, "FUNCTION", "switch_no_biz", (short*)&g_ssl_prog_para.ssl_switch_no_biz,0);

	MESA_load_profile_string_def(filename, "FUNCTION", "STAT_FIELD_APPNAME", g_ssl_prog_para.stat_appname, 16, "SSL");
	MESA_load_profile_string_def(filename, "FUNCTION", "STAT_FIELD_DST_IP", g_ssl_prog_para.stat_dst_ip, 64, "127.0.0.1");
	MESA_load_profile_int_def(filename, "FUNCTION", "STAT_FIELD_DST_PORT", &g_ssl_prog_para.stat_dst_port, 8125);

	return 0;
}

int ssl_add_proto_tag(int projetc_id, struct streaminfo *a_stream, const char* value, int len)
{
	if(projetc_id < 0)return -1;    
	struct ssl_proto_tag_t* proto_tag = (struct ssl_proto_tag_t*)project_req_get_struct(a_stream,projetc_id);   
	if(proto_tag == NULL)   
	{        
		proto_tag = (struct ssl_proto_tag_t *)calloc(sizeof(struct ssl_proto_tag_t), 1);        
		if(0 != project_req_add_struct(a_stream, projetc_id, proto_tag))        
		{            
			free(proto_tag);            
			return -1;        
		}    
	}    
	memcpy(proto_tag->buf, value, len);  
	proto_tag->buf[len]='\0';
	return 0;
}

void ssl_proto_tag_free(int thread_seq, void *value)
{    
	free(value);    
	return;
}

int SSL_INIT(void)
{
	int 	value = 0;		
	memset(&g_ssl_prog_para,0,sizeof(ssl_prog_runtime_parameter_t));	
	strcat(g_ssl_prog_para.ssl_conf_filename, "./conf/ssl/ssl.conf");
	
	if(0!=ssl_readconf(g_ssl_prog_para.ssl_conf_filename))
		return -1;	

	ssl_readMainConf("./conf/ssl/ssl_main.conf");

	/*MESA_proto*/
	g_ssl_prog_para.proto_tag_id  = project_producer_register("MESA_PROTO","struct",ssl_proto_tag_free);

	
	if(g_ssl_prog_para.stat_cycle)
	{	
		g_ssl_prog_para.stat_handler = FS_create_handle();
		FS_set_para(g_ssl_prog_para.stat_handler, OUTPUT_DEVICE, g_ssl_prog_para.stat_filename, strlen(g_ssl_prog_para.stat_filename)+1);
		value = 1;//flush by date
		FS_set_para(g_ssl_prog_para.stat_handler, FLUSH_BY_DATE, &value, sizeof(value));	
		value = 2;//append
		FS_set_para(g_ssl_prog_para.stat_handler, PRINT_MODE, &value, sizeof(value));	
		FS_set_para(g_ssl_prog_para.stat_handler, STAT_CYCLE, &g_ssl_prog_para.stat_cycle, sizeof(g_ssl_prog_para.stat_cycle));
		value = (g_ssl_prog_para.stat_cycle!=0) ? 1 : 0;
		FS_set_para(g_ssl_prog_para.stat_handler, PRINT_TRIGGER, &value, sizeof(value));
		value = 1;
		FS_set_para(g_ssl_prog_para.stat_handler, CREATE_THREAD, &value, sizeof(value));	
		FS_set_para(g_ssl_prog_para.stat_handler, APP_NAME, g_ssl_prog_para.stat_appname, strlen(g_ssl_prog_para.stat_appname)+1);
		FS_set_para(g_ssl_prog_para.stat_handler, STATS_SERVER_IP, g_ssl_prog_para.stat_dst_ip, strlen(g_ssl_prog_para.stat_dst_ip)+1);
		FS_set_para(g_ssl_prog_para.stat_handler, STATS_SERVER_PORT, &g_ssl_prog_para.stat_dst_port, sizeof(g_ssl_prog_para.stat_dst_port));
		g_ssl_prog_para.stat_field[SSL_STAT_PKTS_C2S] = FS_register(g_ssl_prog_para.stat_handler,FS_STYLE_FIELD,FS_CALC_CURRENT,"ssl_c2s_pkts");
		g_ssl_prog_para.stat_field[SSL_STAT_PKTS_S2C] = FS_register(g_ssl_prog_para.stat_handler,FS_STYLE_FIELD,FS_CALC_CURRENT,"ssl_s2c_pkts");
		g_ssl_prog_para.stat_field[SSL_STAT_BITS_C2S] = FS_register(g_ssl_prog_para.stat_handler,FS_STYLE_FIELD,FS_CALC_CURRENT,"ssl_c2s_bytes");
		g_ssl_prog_para.stat_field[SSL_STAT_BITS_S2C] = FS_register(g_ssl_prog_para.stat_handler,FS_STYLE_FIELD,FS_CALC_CURRENT,"ssl_s2c_bytes");	
		FS_start(g_ssl_prog_para.stat_handler);
	}
	return 0;
}/*SSL_INIT*/

void SSL_DESTROY(void)
{
	return;
}/*SSL_DESTRORY*/

void SSL_GETPLUGID(unsigned short plugid)
{
	g_ssl_prog_para.ssl_plugid = plugid;
}

void SSL_PROT_FUNSTAT(unsigned long long protflag)
{
	if(0==protflag)	return;

	g_ssl_prog_para.ssl_interested_region_flag = protflag;
	return;
}/*PROT_FUNSTAT*/

unsigned long long ssl_getRegionID(char *string, int str_len, char g_string[MAX_REGION_NUM][REGION_NAME_LEN])
{
	unsigned long long i=0;
	for(i=0;i<g_ssl_prog_para.ssl_region_cnt;i++)
	{		
        if(0==strcasecmp(g_string[i], string))
		{
			return i;
		}
	}
	return 0;
}

long long SSL_FLAG_CHANGE(char* flag_str)
{
	if(flag_str==NULL) return -1;
	
	long long protflag = 0;
	long long region_id = 0;	
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
		region_id = ssl_getRegionID(region_name, strlen(region_name), g_ssl_prog_para.ssl_conf_regionname);
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

UCHAR ssl_doWithInsterestedRegion(struct streaminfo *a_tcp)
{
	/*业务层没有注册兴趣域*/
	if(g_ssl_prog_para.ssl_interested_region_flag < SSL_KEY)		return APP_STATE_DROPME;
	
	return SSL_RETURN_NORM;
}/*ssl_doWithInsterestedRegion*/

void ssl_initStructClientHello(st_client_hello_t* pstClientHello)
{
	if(pstClientHello==NULL) return ;

	pstClientHello->session.session_value = NULL;
	pstClientHello->session.session_len = 0;
	pstClientHello->ciphersuits.suite_value = NULL;
	pstClientHello->ciphersuits.suite_len = 0;
	pstClientHello->com_method.methods = NULL;
	pstClientHello->com_method.methlen = 0;
	memset(&pstClientHello->random, 0, sizeof(pstClientHello->random));
	int i=0;
	for(i=0;i<MAX_EXTENSION_NUM;i++)
	{
		memset(&pstClientHello->exts[i], 0, sizeof(pstClientHello->exts[i]));

	}
	memset(&pstClientHello->server_name, 0, sizeof(pstClientHello->server_name));
	return;
}

void ssl_initStructServerHello(st_server_hello_t* pstServerHello)
{
	if(pstServerHello==NULL) return ;

	pstServerHello->session.session_value = NULL;
	pstServerHello->session.session_len = 0;
	pstServerHello->ciphersuits.suite_value = NULL;
	pstServerHello->ciphersuits.suite_len = 0;
	pstServerHello->com_method.methods = NULL;
	pstServerHello->com_method.methlen = 0;
	memset(&pstServerHello->random, 0, sizeof(pstServerHello->random));	
	return;
}

int ssl_initSslStream(struct streaminfo *a_tcp, void **pme, int thread_seq)
{
    /**Variables define**/
    ssl_stream *a_ssl_stream = (ssl_stream *)*pme;   

    if(NULL != a_ssl_stream)
    	return -1;

    a_ssl_stream = (ssl_stream *)dictator_malloc(thread_seq, sizeof(ssl_stream));
	memset(a_ssl_stream,0,sizeof(ssl_stream));
    if (NULL == a_ssl_stream)
    {
        return -1;
    }

    a_ssl_stream->output_region_flag = g_ssl_prog_para.ssl_interested_region_flag; 

    a_ssl_stream->uiMaxBuffLen = 0;
	a_ssl_stream->uiCurBuffLen = 0;
    a_ssl_stream->uiMsgState = SSL_HANDSHAKE_NOTRUNK;
    a_ssl_stream->uiSslVersion = UNKNOWN_VERSION;  
    a_ssl_stream->uiAllMsgLen = 0;
    a_ssl_stream->ucContType = 0;
    a_ssl_stream->link_state = SSL_FLASE;
    a_ssl_stream->over_flag = SSL_FLASE;
	a_ssl_stream->is_ssl_stream = SSL_FLASE;

	//memset(a_ssl_stream->pcSslBuffer, 0, sizeof(a_ssl_stream->pcSslBuffer));
	//ssl_stream->pcSslBuffer = NULL;
	a_ssl_stream->p_output_buffer = (cdata_buf*)dictator_malloc(thread_seq, sizeof(cdata_buf));
	a_ssl_stream->p_output_buffer->data_size = 0;	
	a_ssl_stream->p_output_buffer->p_data = 0;	

	/*
	a_ssl_stream->stSSLCert = (st_cert_t*)dictator_malloc(thread_seq,sizeof(st_cert_t));
	memset(a_ssl_stream->stSSLCert, 0, sizeof(a_ssl_stream->stSSLCert));

	a_ssl_stream->stClientHello = (st_client_hello_t*)dictator_malloc(thread_seq,sizeof(st_client_hello_t));
	memset(a_ssl_stream->stClientHello, 0, sizeof(a_ssl_stream->stClientHello));
	ssl_initStructClientHello(a_ssl_stream->stClientHello);

	a_ssl_stream->stServerHello = (st_server_hello_t*)dictator_malloc(thread_seq,sizeof(st_server_hello_t));
	memset(a_ssl_stream->stServerHello, 0, sizeof(a_ssl_stream->stServerHello));	
	ssl_initStructServerHello(a_ssl_stream->stServerHello);
	*/
	a_ssl_stream->output_region_mask = SSL_INTEREST_KEY_MASK;

	a_ssl_stream->business = (business_infor_t *)dictator_malloc(thread_seq,sizeof(business_infor_t));
	a_ssl_stream->business->param = NULL;
	a_ssl_stream->business->return_value = PROT_STATE_GIVEME; 
	
    *pme = (void*)a_ssl_stream;
    return 0;
}


void ssl_releaseStructClientHello(int thread_seq, st_client_hello_t* pstClientHello)
{
	if(pstClientHello==NULL) return ;
	if(pstClientHello->session.session_value!=NULL)
	{
		dictator_free(thread_seq,pstClientHello->session.session_value);
		pstClientHello->session.session_value = NULL;
	}
	if(pstClientHello->ciphersuits.suite_value!=NULL)
	{
		dictator_free(thread_seq,pstClientHello->ciphersuits.suite_value);
		pstClientHello->ciphersuits.suite_value = NULL;
	}
	if(pstClientHello->com_method.methods!=NULL)
	{
		dictator_free(thread_seq,pstClientHello->com_method.methods);
		pstClientHello->com_method.methods = NULL;
	}
	return;
}



void ssl_releaseStructServerHello(int thread_seq,st_server_hello_t* pstServerHello)
{
	if(pstServerHello==NULL) return ;
	if(pstServerHello->session.session_value!=NULL)
	{
		dictator_free(thread_seq,pstServerHello->session.session_value);
		pstServerHello->session.session_value = NULL;
	}
	if(pstServerHello->ciphersuits.suite_value!=NULL)
	{
		dictator_free(thread_seq,pstServerHello->ciphersuits.suite_value);
		pstServerHello->ciphersuits.suite_value = NULL;
	}
	if(pstServerHello->com_method.methods!=NULL)
	{
		dictator_free(thread_seq,pstServerHello->com_method.methods);
		pstServerHello->com_method.methods = NULL;
	}
	return ;
}

void ssl_releaseSslStream(struct streaminfo *a_tcp, ssl_stream** pme, int thread_seq,void *a_packet)
{
	ssl_stream *a_ssl_stream = (ssl_stream *)*pme;
	if(NULL == a_ssl_stream)	return;

	(a_ssl_stream)->over_flag = SSL_TRUE;

	if(a_ssl_stream->uiSslVersion!=UNKNOWN_VERSION)
	{
		ssl_callPlugins(&a_ssl_stream, a_tcp, a_ssl_stream->output_region_flag, thread_seq, a_packet);
	}

	if(NULL !=	a_ssl_stream->p_output_buffer)
	{
		if(a_ssl_stream->p_output_buffer->p_data!=NULL)
		{
			dictator_free(thread_seq,a_ssl_stream->p_output_buffer->p_data);
			a_ssl_stream->p_output_buffer->p_data = NULL;
		}
		dictator_free(thread_seq,a_ssl_stream->p_output_buffer);
	}
	if(NULL != a_ssl_stream->business)
	{
		dictator_free(thread_seq,a_ssl_stream->business);
		a_ssl_stream->business = NULL;
	}
	if(NULL !=  a_ssl_stream->stSSLCert)
	{		
		dictator_free(thread_seq,a_ssl_stream->stSSLCert);
		a_ssl_stream->stSSLCert = NULL;
	}
	if(NULL !=  a_ssl_stream->stClientHello)
	{
		ssl_releaseStructClientHello(thread_seq, a_ssl_stream->stClientHello);
		dictator_free(thread_seq,a_ssl_stream->stClientHello);
		a_ssl_stream->stClientHello = NULL;
	}
	if(NULL !=  a_ssl_stream->stServerHello)
	{
		ssl_releaseStructServerHello(thread_seq, a_ssl_stream->stServerHello);
		dictator_free(thread_seq,a_ssl_stream->stServerHello);
		a_ssl_stream->stServerHello = NULL;
	}

	if(a_ssl_stream->pcSslBuffer!=NULL)
	{
		dictator_free(thread_seq,a_ssl_stream->pcSslBuffer);
	}
		
	dictator_free(thread_seq,a_ssl_stream);
	a_ssl_stream = NULL;
    return;
}

char SSL_ENTRY(struct streaminfo *a_tcp, void**pme, int thread_seq, void *a_packet)
{
	UCHAR return_val=0;
	ssl_stream *a_ssl_stream = NULL;

	if(!g_ssl_prog_para.ssl_switch_no_biz)
	{
	    switch(ssl_doWithInsterestedRegion(a_tcp))
	    {
	    case APP_STATE_DROPME:
	    	return APP_STATE_DROPME;   
	    default:
	    	break;
	    }
	}

    switch(a_tcp->opstate)
    {
    case OP_STATE_PENDING:
    	ssl_initSslStream(a_tcp, pme,thread_seq);
	case OP_STATE_DATA:
      return_val = ssl_analyseStream(a_tcp, pme ,thread_seq, a_packet);
    	a_ssl_stream = (ssl_stream *)*pme;
    	if(APP_STATE_DROPME==return_val ||  SSL_RETURN_DROPME==return_val)
    	{
    		ssl_releaseSslStream(a_tcp, &a_ssl_stream, thread_seq,a_packet);
    		*pme = NULL;
    		return APP_STATE_DROPME;
    	}
       	break;

    case OP_STATE_CLOSE:
    	a_ssl_stream = (ssl_stream *)*pme;
        if(a_ssl_stream!=NULL)
		{
			a_ssl_stream->over_flag = SSL_TRUE;
		}
		if(a_ssl_stream->uiSslVersion!=UNKNOWN_VERSION)
		{			
			ssl_add_proto_tag(g_ssl_prog_para.proto_tag_id, a_tcp, "SSL", strlen("SSL"));
			if(g_ssl_prog_para.stat_cycle)
			{			
				atomic_add(&g_ssl_prog_para.stat_value[SSL_STAT_PKTS_C2S], a_tcp->ptcpdetail->serverpktnum);
				atomic_add(&g_ssl_prog_para.stat_value[SSL_STAT_PKTS_S2C], a_tcp->ptcpdetail->clientpktnum);
				atomic_add(&g_ssl_prog_para.stat_value[SSL_STAT_BITS_C2S], a_tcp->ptcpdetail->serverbytes);
				atomic_add(&g_ssl_prog_para.stat_value[SSL_STAT_BITS_S2C], a_tcp->ptcpdetail->clientbytes);
				
				FS_operate(g_ssl_prog_para.stat_handler, g_ssl_prog_para.stat_field[SSL_STAT_PKTS_C2S],0, FS_OP_SET, g_ssl_prog_para.stat_value[SSL_STAT_PKTS_C2S]);
				FS_operate(g_ssl_prog_para.stat_handler, g_ssl_prog_para.stat_field[SSL_STAT_PKTS_S2C],0, FS_OP_SET, g_ssl_prog_para.stat_value[SSL_STAT_PKTS_S2C]);
				FS_operate(g_ssl_prog_para.stat_handler, g_ssl_prog_para.stat_field[SSL_STAT_BITS_C2S],0, FS_OP_SET, g_ssl_prog_para.stat_value[SSL_STAT_BITS_C2S]);
				FS_operate(g_ssl_prog_para.stat_handler, g_ssl_prog_para.stat_field[SSL_STAT_BITS_S2C],0, FS_OP_SET, g_ssl_prog_para.stat_value[SSL_STAT_BITS_S2C]);
			}
		}
    	return_val = ssl_analyseStream(a_tcp, pme ,thread_seq, a_packet);    	
    	if(NULL!=a_ssl_stream)
    	{
    		ssl_releaseSslStream(a_tcp, &a_ssl_stream, thread_seq,a_packet);
    		*pme = NULL;
    	}  				
		
    	return APP_STATE_DROPME;
    }
    return APP_STATE_GIVEME;
}

