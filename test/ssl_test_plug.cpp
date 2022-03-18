/*
 *  author:yangwei
 *  create time:2021-8-21
 *
 */



#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>

#include "SSL_Analyze.h"
#include "ssl.h"
#include "SSL_Message.h"
#include "SSL_Certificate.h"
#include "SSL_Proc.h"
#include "cJSON.h"
#include "MESA_prof_load.h"
#include <MESA/stream.h>

extern "C" int commit_test_result_json(cJSON *node, const char *name);

static int g_result_count = 1;

static char *ssl_test_assemble_san(st_cert_t *cert)
{
	char *san_buf=NULL;
	int total_buflen = 0;
	for (int i = 0; i < cert->SSLSubAltName->count; i++)
	{
		int tmp_buflen = strlen(cert->SSLSubAltName->san_array[i].san);
		char *tmp_buf = (char *)realloc(san_buf, total_buflen+tmp_buflen+1);
		if(tmp_buf==NULL)
		{
			free(san_buf);
			san_buf=NULL;
			break;
		}
		
		san_buf=tmp_buf;
		san_buf[total_buflen + tmp_buflen] = ';';
		memcpy(san_buf+total_buflen, cert->SSLSubAltName->san_array[i].san, tmp_buflen);
		total_buflen+=tmp_buflen+1;
	}

	if(san_buf!=NULL)
	{
		san_buf[total_buflen-1] = '\0';
	}
	return san_buf;
}

extern "C" unsigned char SSL_TEST_PLUG_ENTRY(stSessionInfo *session_info, void **pme, int thread_seq, struct streaminfo *a_tcp, void *a_packet)
{
    assert(NULL != session_info || pme != NULL);

    cJSON *ctx = (cJSON *)*pme;
	st_cert_t *cert=NULL;
    ssl_stream *a_ssl = (ssl_stream *)(session_info->app_info);
    
    if (session_info->session_state & SESSION_STATE_PENDING)
    {
        if (*pme == NULL)
        {
            ctx = cJSON_CreateObject();
            *pme = (void *)ctx;
            cJSON_AddStringToObject(ctx, "Tuple4", printaddr(&a_tcp->addr, a_tcp->threadnum));
        }
    }

    switch (session_info->prot_flag)
    {
        case SSL_CLIENT_HELLO:
	        if (a_ssl== NULL || a_ssl->stClientHello==NULL)
	        {
	        	break;
	        }
			
			if(a_ssl->stClientHello->server_name!=NULL && strlen((char *)(a_ssl->stClientHello->server_name))>0)
			{
				cJSON_AddStringToObject(ctx, (const char*)"ssl_sni", (const char*)(a_ssl->stClientHello->server_name));
			}

			if(a_ssl->stClientHello->encrypted_server_name.esni!=NULL)
			{
				cJSON_AddStringToObject(ctx, (const char*)"ssl_sni", "ESNI");
			}

			if(ssl_get_version_name(a_ssl->stClientHello->client_ver))
			{
				cJSON_AddStringToObject(ctx, "ssl_client_version", ssl_get_version_name(a_ssl->stClientHello->client_ver));
			}
            break;
        case SSL_CERTIFICATE_DETAIL:
			if (a_ssl==NULL || a_ssl->stSSLCert==NULL || a_tcp->curdir==DIR_C2S)
			{
				break;
			}

			cert = a_ssl->stSSLCert;
			if (cert->cert_type != CERT_TYPE_INDIVIDUAL)
			{
				break;
			}

			if (strlen(cert->SSLVersion) > 0)
			{
				cJSON_AddStringToObject(ctx, "ssl_cert_version", cert->SSLVersion);
			}
	
			if(strlen(cert->SSLIssuer)>0)
			{
				cJSON_AddStringToObject(ctx, "ssl_cert_Issuer", cert->SSLIssuer);
				
				if (cert->SSLIssuerCN != NULL && strlen(cert->SSLIssuerCN) > 0)
				{
					cJSON_AddStringToObject(ctx, "ssl_cert_IssuerCN", cert->SSLIssuerCN);
				}
			
				if (cert->SSLIssuerO != NULL && strlen(cert->SSLIssuerO) > 0)
				{
					cJSON_AddStringToObject(ctx, "ssl_cert_IssuerO", cert->SSLIssuerO);
				}

				if (cert->SSLIssuerC != NULL && strlen(cert->SSLIssuerC) > 0)
				{
					cJSON_AddStringToObject(ctx, "ssl_cert_IssuerC", cert->SSLIssuerC);
				}
			
				if (cert->SSLIssuerP != NULL && strlen(cert->SSLIssuerP) > 0)
				{
					cJSON_AddStringToObject(ctx, "ssl_cert_IssuerP", cert->SSLIssuerP);
				}
			
				if (cert->SSLIssuerL != NULL && strlen(cert->SSLIssuerL) > 0)
				{
					cJSON_AddStringToObject(ctx, "ssl_cert_IssuerL", cert->SSLIssuerL);
				}
			
				if (cert->SSLIssuerS != NULL && strlen(cert->SSLIssuerS) > 0)
				{
					cJSON_AddStringToObject(ctx, "ssl_cert_IssuerS", cert->SSLIssuerS);
				}
			
				if (cert->SSLIssuerU != NULL && strlen(cert->SSLIssuerU) > 0)
				{
					cJSON_AddStringToObject(ctx, "ssl_cert_IssuerU", cert->SSLIssuerU);
				}
			}
			
			if(strlen(cert->SSLSub)>0)
			{						
				cJSON_AddStringToObject(ctx, "ssl_cert_Sub", cert->SSLSub);
				
				if (cert->SSLSubCN != NULL && strlen(cert->SSLSubCN) > 0)
				{
					cJSON_AddStringToObject(ctx, "ssl_cert_SubCN", cert->SSLSubCN);
				}
				
				if (cert->SSLSubO != NULL && strlen(cert->SSLSubO) > 0)
				{
					cJSON_AddStringToObject(ctx, "ssl_cert_SubO", cert->SSLSubO);
				}
				
				if (cert->SSLSubC != NULL && strlen(cert->SSLSubC) > 0)
				{
					cJSON_AddStringToObject(ctx, "ssl_cert_SubC", cert->SSLSubC);
				}
				
				if (cert->SSLSubP != NULL && strlen(cert->SSLSubP) > 0)
				{
					cJSON_AddStringToObject(ctx, "ssl_cert_SubP", cert->SSLSubP);
				}
				
				if (cert->SSLSubL != NULL && strlen(cert->SSLSubL) > 0)
				{
					cJSON_AddStringToObject(ctx, "ssl_cert_SubL", cert->SSLSubL);
				}
				
				if (cert->SSLSubS != NULL && strlen(cert->SSLSubS) > 0)
				{
					cJSON_AddStringToObject(ctx, "ssl_cert_SubS", cert->SSLSubS);
				}
				
				if (cert->SSLSubU != NULL && strlen(cert->SSLSubU) > 0)
				{
					cJSON_AddStringToObject(ctx, "ssl_cert_SubU", cert->SSLSubU);
				}
			}
			
			if (cert->SSLSubCN!=NULL)
			{
				cJSON_AddStringToObject(ctx, "ssl_cert_SubCN", cert->SSLSubCN);
			}
			
			if (cert->SSLSubAltName != NULL && cert->SSLSubAltName->count > 0)
			{
					char *san_buf = ssl_test_assemble_san(cert);
					cJSON_AddStringToObject(ctx, "ssl_cert_SubAltName", san_buf);
					free(san_buf);
					san_buf=NULL;
			}

			if(cert->SSLSerialNumLen>0)
			{
				char *serialBuf=(char *)calloc(1, cert->SSLSerialNumLen*2+1+2);
				int offset=snprintf(serialBuf, 3, "0x");
				for(int i=0; i<cert->SSLSerialNumLen; i++)
				{
					offset+=snprintf(serialBuf+offset, cert->SSLSerialNumLen*2+1+2-offset, "%02hhx", (unsigned char )(cert->SSLSerialNum[i]));
				}
				
				cJSON_AddStringToObject(ctx, "ssl_cert_SerialNum", serialBuf);
				free(serialBuf);
				serialBuf=NULL;
			}

			if(strlen(cert->SSLAgID)>0)
			{
				cJSON_AddStringToObject(ctx, "ssl_cert_AgID", cert->SSLAgID);
			}

			if(strlen(cert->SSLFPAg)>0)
			{
				cJSON_AddStringToObject(ctx, "ssl_cert_FPAg", cert->SSLFPAg);
			}

			if(strlen(cert->SSLFrom)>0)
			{
				cJSON_AddStringToObject(ctx, "ssl_cert_From", cert->SSLFrom);
			}

			if(strlen(cert->SSLTo)>0)
			{
				cJSON_AddStringToObject(ctx, "ssl_cert_To", cert->SSLTo);
			}
            break;
        default:
            break;
    }

    if(session_info->session_state&SESSION_STATE_CLOSE)
    {
            if(ctx)
            {
                char result_name[16]="";
                sprintf(result_name,"SSL_RESULT_%d", g_result_count);
                commit_test_result_json(ctx, result_name);
                g_result_count+=1;
            }
            *pme = NULL;
            return PROT_STATE_DROPME;

    }

    return PROT_STATE_GIVEME;

}

extern "C" int SSL_TEST_PLUG_INIT()
{
    return 0;
}

extern "C" void SSL_TEST_PLUG_DESTROY(void)
{
    return ;
}/*CHAR_DESTRORY*/



