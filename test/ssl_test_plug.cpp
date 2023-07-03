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

static char *ssl_test_assemble_san(struct ssl_certificate *certificate)
{
	char *san_buf=NULL;
	int total_buflen = 0;
	for (int i = 0; i < certificate->subject_alter.num; i++)
	{
		int tmp_buflen=strlen(certificate->subject_alter.name[i]);
		char *tmp_buf=(char *)realloc(san_buf, total_buflen+tmp_buflen+1);
		if(tmp_buf==NULL)
		{
			free(san_buf);
			san_buf=NULL;
			break;
		}
		
		san_buf=tmp_buf;
		san_buf[total_buflen + tmp_buflen] = ';';
		memcpy(san_buf+total_buflen, certificate->subject_alter.name[i], tmp_buflen);
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

    struct ssl_stream *a_ssl = (struct ssl_stream *)(session_info->app_info);
    struct ssl_ja3_info *ja3_info = NULL;
    
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
	        if (a_ssl== NULL || a_ssl->chello==NULL)
	        {
	        	break;
	        }

		if (strlen((char *)(a_ssl->chello->server_name)) > 0)
		{
			cJSON_AddStringToObject(ctx, (const char *)"ssl_sni", (const char *)(a_ssl->chello->server_name));
		}
		if (a_ssl->chello->encrypt_chello != NULL)
		{
			cJSON_AddStringToObject(ctx, (const char *)"ssl_ech", "1");
		}

		if (a_ssl->chello->esni.is_esni==1)
		{
			cJSON_AddStringToObject(ctx, (const char *)"ssl_sni", "ESNI");
		}

		if (ssl_get_version_name(a_ssl->chello->version) != NULL)
		{
			cJSON_AddStringToObject(ctx, "ssl_client_version", ssl_get_version_name(a_ssl->chello->version));
		}

		ja3_info = ssl_get_ja3_fingerprint(a_tcp, (unsigned char *)a_tcp->ptcpdetail->pdata, (unsigned int)a_tcp->ptcpdetail->datalen, a_tcp->threadnum);
		if (ja3_info != NULL && ja3_info->fp != NULL && ja3_info->fp_len > 0)
		{
			cJSON_AddStringToObject(ctx, "ssl_ja3_hash", ja3_info->fp);
		}

	    break;
	case SSL_SERVER_HELLO:
		if (a_ssl->shello->ja3s.fingerprint_md5 != NULL && a_ssl->shello->ja3s.fingerprint_md5_len > 0)
		{
			cJSON_AddStringToObject(ctx, "ssl_ja3s_hash", a_ssl->shello->ja3s.fingerprint_md5);
		}
		break;
	case SSL_CERTIFICATE_DETAIL:
			if (a_ssl==NULL || a_ssl->certificate==NULL || a_tcp->curdir==DIR_C2S)
			{
				break;
			}

			if (a_ssl->certificate->cert_type != CERT_TYPE_INDIVIDUAL)
			{
				break;
			}

			if(a_ssl->certificate->version.len > 0)
			{
				cJSON_AddStringToObject(ctx, "ssl_cert_version", (const char*)a_ssl->certificate->version.value);
			}
	
			if(strlen(a_ssl->certificate->issuer.rdn_sequence_list)>0)
			{
				cJSON_AddStringToObject(ctx, "ssl_cert_Issuer", a_ssl->certificate->issuer.rdn_sequence_list);
				
				if(strlen(a_ssl->certificate->issuer.common) > 0)
				{
					cJSON_AddStringToObject(ctx, "ssl_cert_IssuerCN", a_ssl->certificate->issuer.common);
				}
			
				if(strlen(a_ssl->certificate->issuer.organization) > 0)
				{
					cJSON_AddStringToObject(ctx, "ssl_cert_IssuerO", a_ssl->certificate->issuer.organization);
				}

				if(strlen(a_ssl->certificate->issuer.country) > 0)
				{
					cJSON_AddStringToObject(ctx, "ssl_cert_IssuerC", a_ssl->certificate->issuer.country);
				}
			
				if(strlen(a_ssl->certificate->issuer.state_or_Province) > 0)
				{
					cJSON_AddStringToObject(ctx, "ssl_cert_IssuerP", a_ssl->certificate->issuer.state_or_Province);
				}
			
				if(strlen(a_ssl->certificate->issuer.locality) > 0)
				{
					cJSON_AddStringToObject(ctx, "ssl_cert_IssuerL", a_ssl->certificate->issuer.locality);
				}
			
				if(strlen(a_ssl->certificate->issuer.street_address) > 0)
				{
					cJSON_AddStringToObject(ctx, "ssl_cert_IssuerS", a_ssl->certificate->issuer.street_address);
				}
			
				if(strlen(a_ssl->certificate->issuer.organizational_unit) > 0)
				{
					cJSON_AddStringToObject(ctx, "ssl_cert_IssuerU", a_ssl->certificate->issuer.organizational_unit);
				}
			}
			
			if(strlen(a_ssl->certificate->subject.rdn_sequence_list)>0)
			{						
				cJSON_AddStringToObject(ctx, "ssl_cert_Sub", a_ssl->certificate->subject.rdn_sequence_list);
				
				if(strlen(a_ssl->certificate->subject.common) > 0)
				{
					cJSON_AddStringToObject(ctx, "ssl_cert_SubCN", a_ssl->certificate->subject.common);
				}
				
				if(strlen(a_ssl->certificate->subject.organization) > 0)
				{
					cJSON_AddStringToObject(ctx, "ssl_cert_SubO", a_ssl->certificate->subject.organization);
				}
				
				if(strlen(a_ssl->certificate->subject.country) > 0)
				{
					cJSON_AddStringToObject(ctx, "ssl_cert_SubC", a_ssl->certificate->subject.country);
				}
				
				if(strlen(a_ssl->certificate->subject.state_or_Province) > 0)
				{
					cJSON_AddStringToObject(ctx, "ssl_cert_SubP", a_ssl->certificate->subject.state_or_Province);
				}
				
				if(strlen(a_ssl->certificate->subject.locality) > 0)
				{
					cJSON_AddStringToObject(ctx, "ssl_cert_SubL", a_ssl->certificate->subject.locality);
				}
				
				if(strlen(a_ssl->certificate->subject.street_address) > 0)
				{
					cJSON_AddStringToObject(ctx, "ssl_cert_SubS", a_ssl->certificate->subject.street_address);
				}
				
				if(strlen(a_ssl->certificate->subject.organizational_unit) > 0)
				{
					cJSON_AddStringToObject(ctx, "ssl_cert_SubU", a_ssl->certificate->subject.organizational_unit);
				}
			}
			
			if(a_ssl->certificate->subject_alter.name != NULL && a_ssl->certificate->subject_alter.num>0)
			{
					char *san_buf = ssl_test_assemble_san(a_ssl->certificate);
					cJSON_AddStringToObject(ctx, "ssl_cert_SubAltName", san_buf);
					free(san_buf);
					san_buf=NULL;
			}

			if(a_ssl->certificate->serial.len>0)
			{
				char *serialBuf=(char *)calloc(1, a_ssl->certificate->serial.len*2+1+2);
				int offset=snprintf(serialBuf, 3, "0x");
				for(int i=0; i<a_ssl->certificate->serial.len; i++)
				{
					offset+=snprintf(serialBuf+offset, a_ssl->certificate->serial.len*2+1+2-offset, "%02hhx", (unsigned char )(a_ssl->certificate->serial.value[i]));
				}
				
				cJSON_AddStringToObject(ctx, "ssl_cert_SerialNum", serialBuf);
				free(serialBuf);
				serialBuf=NULL;
			}

			if(a_ssl->certificate->signature_algorithm.len>0)
			{
				cJSON_AddStringToObject(ctx, "ssl_cert_AgID", (const char*)a_ssl->certificate->signature_algorithm.value);
			}

			if(strlen(a_ssl->certificate->validity.before)>0)
			{
				cJSON_AddStringToObject(ctx, "ssl_cert_From", a_ssl->certificate->validity.before);
			}

			if(strlen(a_ssl->certificate->validity.after)>0)
			{
				cJSON_AddStringToObject(ctx, "ssl_cert_To", a_ssl->certificate->validity.after);
			}

			if(a_ssl->certificate->algorithm_identifier.len>0)
			{
				cJSON_AddStringToObject(ctx, "ssl_cert_SSLFPAg", (const char*)a_ssl->certificate->algorithm_identifier.value);
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



