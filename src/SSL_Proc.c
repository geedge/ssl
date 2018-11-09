/*
 * SSL_Proc.c
 *
 *  Created on: 2013-5-3
 *      Author: lis
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "SSL_Analyze.h"
#include "SSL_Message.h"
#include "ssl.h"
#include "SSL_Proc.h"
#include "SSL_Common.h"

//debug
#define PRINTF_CLIENT_HELLO		0

extern ssl_prog_runtime_parameter_t 	g_ssl_prog_para;

const stValueString_t pastSslVersions[] =
{
    { 0xfeff, "DTLS1.0" },
    { 0x0100, "DTLS1.0(OpenSSL pre 0.9.8f)" },
    { 0x0303, "TLS1.2" },
    { 0x0302, "TLS1.1" },
    { 0x0301, "TLS1.0" },
    { 0x0300, "SSL3.0" },
    { 0x0002, "SSL2.0" },
    { 0x00, NULL }
};


int BtoL4BytesNum(char *pcData)
{
    int uiLength = 0;
    uiLength = pcData[0];
    uiLength = (uiLength << 8) + (unsigned char)pcData[1];
    uiLength = (uiLength << 8) + (unsigned char)pcData[2];
	uiLength = (uiLength << 8) + (unsigned char)pcData[3];
    return uiLength;
}

int BtoL3BytesNum(char *pcData)
{
    int uiLength = 0;
    uiLength = pcData[0];
    uiLength = (uiLength << 8) + (unsigned char)pcData[1];
    uiLength = (uiLength << 8) + (unsigned char)pcData[2];

    return uiLength;
}

int BtoL2BytesNum(char *pcData)
{
    int uiLength = 0;
    uiLength = pcData[0];
    uiLength = (uiLength << 8) + (unsigned char)pcData[1];

    return uiLength;
}

int BtoL1BytesNum(char *pcData)
{
    int uiLength = 0;
    uiLength = pcData[0];

    return uiLength;
}

UCHAR ssl_doWithVersion(ssl_stream **a_ssl_stream, struct streaminfo *a_tcp,
						unsigned long long region_flag, int thread_seq, void *a_packet)
{	
	UCHAR return_val = SSL_RETURN_NORM;	
	if(!(g_ssl_prog_para.ssl_interested_region_flag&SSL_VERSION))	return return_val;
	
	int find_index = -1;
	for(unsigned int i=0;pastSslVersions[i].uiValue!=0;i++)
	{
		if(pastSslVersions[i].uiValue==(*a_ssl_stream)->uiSslVersion)
		{
			find_index = (int)i;
			break;
		}
	}	
	if(-1!=find_index)
	{
		(*a_ssl_stream)->output_region_mask = SSL_VERSION_MASK;
		(*a_ssl_stream)->p_output_buffer->p_data = (char*)pastSslVersions[find_index].pcString;
		(*a_ssl_stream)->p_output_buffer->data_size = strlen(pastSslVersions[find_index].pcString);
		return_val = ssl_callPlugins(a_ssl_stream, a_tcp, region_flag, thread_seq, a_packet);
		(*a_ssl_stream)->p_output_buffer->p_data = NULL;
		(*a_ssl_stream)->p_output_buffer->data_size = 0;
		(*a_ssl_stream)->output_region_mask = SSL_INTEREST_KEY_MASK;
	}
	return return_val;
}

UCHAR ssl_doWithApplicationData(ssl_stream **a_ssl_stream, struct streaminfo *a_tcp,
						unsigned long long region_flag, int thread_seq, void *a_packet)
{
	UCHAR return_val = SSL_RETURN_NORM;	
	(*a_ssl_stream)->output_region_mask = SSL_APPLICATION_DATA_MASK;
	return_val = ssl_callPlugins(a_ssl_stream, a_tcp, region_flag, thread_seq, a_packet);
	(*a_ssl_stream)->output_region_mask = SSL_INTEREST_KEY_MASK;
	return return_val;
}

UCHAR ssl_doWithCertificate(ssl_stream **a_ssl_stream, struct streaminfo *a_tcp,
						unsigned long long region_flag, int thread_seq, void *a_packet)
{
	UCHAR return_val = SSL_RETURN_NORM;	
	return_val = ssl_callPlugins(a_ssl_stream, a_tcp, region_flag, thread_seq, a_packet);
	(*a_ssl_stream)->output_region_mask = SSL_INTEREST_KEY_MASK;
	return return_val;
}

UCHAR ssl_doWithCertificateDetail(ssl_stream **a_ssl_stream, struct streaminfo *a_tcp,
						unsigned long long region_flag, int thread_seq, void *a_packet)
{
	UCHAR return_val = SSL_RETURN_NORM;	
	(*a_ssl_stream)->output_region_mask = SSL_CERTIFICATE_DETAIL_MASK;
	return_val = ssl_callPlugins(a_ssl_stream, a_tcp, region_flag, thread_seq, a_packet);
	(*a_ssl_stream)->output_region_mask = SSL_INTEREST_KEY_MASK;
	return return_val;
}

UCHAR ssl_doWithClientHello(ssl_stream **a_ssl_stream, struct streaminfo *a_tcp,
						unsigned long long region_flag, int thread_seq, void *a_packet)
{
	UCHAR return_val = SSL_RETURN_NORM;	
	(*a_ssl_stream)->output_region_mask = SSL_CLIENT_HELLO_MASK;

	/*parse extionsion server_name*/
	int i=0;
	for(i=0; i<(*a_ssl_stream)->stClientHello->ext_num; i++)
	{
		if((*a_ssl_stream)->stClientHello->exts[i].type == SERVER_NAME_EXT_TYPE)
		{
			st_client_server_name_t* pstClientServerName = (st_client_server_name_t*)dictator_malloc(thread_seq,sizeof(st_client_server_name_t));
			unsigned char* cur_data = NULL;
			unsigned char first_server_name = 0;
			unsigned char servernamelen = 0;
			pstClientServerName->server_name_list_len =  (*a_ssl_stream)->stClientHello->exts[i].len;
			cur_data =  (*a_ssl_stream)->stClientHello->exts[i].data;
			
			pstClientServerName->server_name_list_len -= sizeof(pstClientServerName->server_name_list_len);
			cur_data += sizeof(pstClientServerName->server_name_list_len);

			/*3=sizeof(pstClientServerName.server_name_type)+sizeof(pstClientServerName.server_name_len)*/
			while(pstClientServerName->server_name_list_len>3)
			{				
				pstClientServerName->server_name_type = BtoL2BytesNum((char *)cur_data);
				pstClientServerName->server_name_len = BtoL1BytesNum((char *)(cur_data+2));
				pstClientServerName->server_name_list_len -= 3;
				/*have data*/
				if(((pstClientServerName->server_name_type == SERVER_NAME_HOST_TYPE)||
                            (pstClientServerName->server_name_type == SERVER_NAME_OTHER_TYPE))&&
                            pstClientServerName->server_name_len>0&&
                            pstClientServerName->server_name_list_len>=pstClientServerName->server_name_len)
				{
					pstClientServerName->server_name_data = cur_data+3;			
					//if(!first_server_name)
					{
						memcpy((*a_ssl_stream)->stClientHello->server_name,
							   pstClientServerName->server_name_data, 
							   pstClientServerName->server_name_len);
						servernamelen = strlen((char*)(*a_ssl_stream)->stClientHello->server_name);
						(*a_ssl_stream)->stClientHello->server_name[servernamelen] = '\0';
						first_server_name = 1;                                        
                                       pstClientServerName->server_name_list_len -= pstClientServerName->server_name_len;
                                       cur_data += pstClientServerName->server_name_len;
                                     
#if PRINTF_CLIENT_HELLO
		//printf("server_name:%s\n",(*a_ssl_stream)->stClientHello->server_name);	
		FILE*				pFile					= NULL;
		time_t			currTime;
		struct tm		 *now;
		char		 strTime[32];
		char		 logTime[32];
		char filename[64] = {0};
		time(&currTime);
		now = localtime(&currTime);
		memset(strTime, 0, sizeof(strTime) );
		memset(logTime, 0, sizeof(logTime) );
		strftime(strTime, sizeof(strTime), "%Y-%m-%d %H:%M:%S", now);
		strftime(logTime, sizeof(logTime), "%Y-%m-%d", now);
		strcpy(filename, "./ssl_log/ssl_server_name_log_"); 
		strcat(filename, logTime);
		if(((pFile = fopen(filename, "a+"))!=NULL))
		{				
			fprintf(pFile,"%s===%s\n",strTime, (*a_ssl_stream)->stClientHello->server_name);
			fclose(pFile);	
		}
#endif
                                    
                                       break;
					}                               
				}				
				cur_data += 3;
			}

             if(NULL!=pstClientServerName) dictator_free(thread_seq,pstClientServerName);
            break;            
		}		
	}	
	
	return_val = ssl_callPlugins(a_ssl_stream, a_tcp, region_flag, thread_seq, a_packet);
    (*a_ssl_stream)->output_region_mask = SSL_INTEREST_KEY_MASK;
	return return_val;
}

UCHAR ssl_doWithServerHello(ssl_stream **a_ssl_stream, struct streaminfo *a_tcp,
						unsigned long long region_flag, int thread_seq, void *a_packet)
{
	UCHAR return_val = SSL_RETURN_NORM;	
	(*a_ssl_stream)->output_region_mask = SSL_SERVER_HELLO_MASK;
	return_val = ssl_callPlugins(a_ssl_stream, a_tcp, region_flag, thread_seq, a_packet);
	(*a_ssl_stream)->output_region_mask = SSL_INTEREST_KEY_MASK;
	return return_val;
}

int ssl_getLinkState(ssl_stream *a_ssl_stream)
{
	UCHAR state = 0;
	if(SSL_FLASE==(a_ssl_stream)->link_state)
	{
		if(SSL_TRUE==(a_ssl_stream)->over_flag)
			state = SESSION_STATE_CLOSE | SESSION_STATE_PENDING;
		else
			state = SESSION_STATE_PENDING;
	}
	else
	{
		if(SSL_TRUE==(a_ssl_stream)->over_flag)
		{
			state = SESSION_STATE_CLOSE;
		}
		else
			state = SESSION_STATE_DATA;
	}
	(a_ssl_stream)->link_state = SSL_TRUE;
	return state;
}/*ssl_getLinkState*/

UCHAR ssl_callPlugins(ssl_stream **a_ssl_stream, struct streaminfo *a_tcp,
		 				  unsigned long long region_flag, int thread_seq, void *a_packet)
{	
	stSessionInfo session_info;
	region_flag = (region_flag >> (*a_ssl_stream)->output_region_mask) % 2;
	
	if( SSL_TRUE==region_flag || (*a_ssl_stream)->over_flag==SSL_TRUE )
	{
		if (PROT_STATE_DROPME != (*a_ssl_stream)->business->return_value)
		{		
			session_info.plugid = g_ssl_prog_para.ssl_plugid;
			session_info.prot_flag = (((unsigned long long)1)<<(*a_ssl_stream)->output_region_mask);			
			session_info.session_state = ssl_getLinkState(*a_ssl_stream) ;			
			session_info.app_info =  (void*)(*a_ssl_stream);
			session_info.buf = (*a_ssl_stream)->p_output_buffer->p_data;
			session_info.buflen = (*a_ssl_stream)->p_output_buffer->data_size;
		   (*a_ssl_stream)->business->return_value = PROT_PROCESS(&session_info,
											&((*a_ssl_stream)->business->param),
											thread_seq,a_tcp, a_packet);
		}
	}
	/*
	if(PROT_STATE_DROPME == (*a_ssl_stream)->business->return_value)
	{
		return PROT_STATE_DROPME;
	}
	*/
	return SSL_RETURN_NORM;
}

/*
Input:       pLenBytes  return the bytes of the length domain
Return:     length of the tlv structure
*/
int fn_iSslDecodeTagLength(char *pcTlvData, int iDataLen, int *pLenBytes)
{
    unsigned int uiLength = 0;
    int iLoop = 0;
    unsigned char *pucTlvData = (unsigned char *)pcTlvData;
    if (NULL == pucTlvData || iDataLen < 2 || NULL == pLenBytes)
    {
        return -1;
    }

    if (pucTlvData[1] > 0x80)
    {
        *pLenBytes = pucTlvData[1] & 0x7f;
    }
    else if (pucTlvData[1] == 0x80)
    {
        *pLenBytes = 1;
        return 0;
    }
    else
    {
        *pLenBytes = 1;
        return pucTlvData[1];
    }

    if (*pLenBytes > iDataLen - 2 || *pLenBytes > 4)
    {
        return -1;
    }

    for (iLoop = 0; iLoop < *pLenBytes; ++iLoop)
    {
        uiLength = (uiLength << 8) + pucTlvData[2+iLoop];
    }

    *pLenBytes += 1;

    return uiLength;
}


void fn_vMemCpy(char *pcDst, int iMaxDstLen, char *pcSrc, int iSrcLen)
{
    char *pcBuff = NULL;
    int iLoop = 0;
    if (NULL == pcDst || NULL == pcSrc || pcDst == pcSrc || iMaxDstLen < iSrcLen)
    {
        return;
    }

    if (pcDst < pcSrc || pcDst > pcSrc + iSrcLen)
    {
        pcBuff = pcSrc;
    }
    else
    {
        pcBuff = (char *)malloc(sizeof(char)*iSrcLen);
        if (NULL == pcBuff)
        {
            return;
        }

        memcpy(pcBuff, pcSrc, iSrcLen);
    }

    for (iLoop = 0; iLoop < iSrcLen; ++iLoop)
    {
        pcDst[iLoop] = pcSrc[iLoop];
    }

    if (pcBuff != pcSrc)
    {
        free(pcBuff);
    }

    return;
}

void fn_vPrintNum(char *pcDstBuff, unsigned char ucNum)
{
    if (NULL == pcDstBuff)
    {
        return;
    }

    if ((((ucNum&0xf0)>>4)&0x0f) < 0x0a)
    {
        pcDstBuff[0] = 0x30 + (((ucNum&0xf0)>>4)&0x0f);
    }
    else
    {
        pcDstBuff[0] = 0x61 - 0x0a + (((ucNum&0xf0)>>4)&0x0f);
    }

    if ((ucNum&0x0f) < 0x0a)
    {
        pcDstBuff[1] = 0x30 + (ucNum&0x0f);
    }
    else
    {
        pcDstBuff[1] = 0x61 - 0x0a + (ucNum&0x0f);
    }

    pcDstBuff[2] = '\0';
    return;
}
