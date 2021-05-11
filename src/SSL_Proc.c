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
    { DTLSV1_0_VERSION, 	"DTLS1.0" },
    { DTLSV1_0_VERSION_NOT, "DTLS1.0(OpenSSL pre 0.9.8f)" },  
    { TLSV1_2_VERSION, 		"TLS1.2" },
    { TLSV1_1_VERSION, 		"TLS1.1" },
    { TLSV1_0_VERSION, 		"TLS1.0" },
    { SSLV3_VERSION, 		"SSL3.0" },
    { SSLV2_VERSION, 		"SSL2.0" },
    { UNKNOWN_VERSION, 		NULL }
};

/*
const stSerialString_t g_astCipherSuit[] =
{
    {{0X00, 0X2f}, "TLS_RSA_WITH_AES_128_CBC_SHA"},
    {{0X00, 0X35}, "TLS_RSA_WITH_AES_256_CBC_SHA"},
    {{0X00, 0X05}, "TLS_RSA_WITH_RC4_128_CBC_SHA"},
    {{0X00, 0X0a}, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
    {{0Xc0, 0X13}, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"},
    {{0Xc0, 0X14}, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"},
    {{0Xc0, 0X09}, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"},
    {{0Xc0, 0X0a}, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"},
    {{0X00, 0X32}, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"},
    {{0X00, 0X38}, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"},
    {{0X00, 0X13}, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"},
    {{0X00, 0X04}, "TLS_RSA_WITH_RC4_128_MD5"},
    {{0X00, 0X39}, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"},
    {{0}, NULL},
};
*/

stSerialString_t g_astCipherSuit[] =
{
	{{0xC0, 0X30}, "ECDHE-RSA-AES256-GCM-SHA384"},	
	{{0xC0, 0X2C}, "ECDHE-ECDSA-AES256-GCM-SHA384"},	
	{{0xC0, 0X28}, "ECDHE-RSA-AES256-SHA384"},	
	{{0xC0, 0X24}, "ECDHE-ECDSA-AES256-SHA384"},	
	{{0xC0, 0X14}, "ECDHE-RSA-AES256-SHA"},	
	{{0xC0, 0X0A}, "ECDHE-ECDSA-AES256-SHA"},	
	{{0x00, 0XA5}, "DH-DSS-AES256-GCM-SHA384"},	
	{{0x00, 0XA3}, "DHE-DSS-AES256-GCM-SHA384"},	
	{{0x00, 0XA1}, "DH-RSA-AES256-GCM-SHA384"},	
	{{0x00, 0X9F}, "DHE-RSA-AES256-GCM-SHA384"},	
	{{0x00, 0X6B}, "DHE-RSA-AES256-SHA256"},	
	{{0x00, 0X6A}, "DHE-DSS-AES256-SHA256"},	
	{{0x00, 0X69}, "DH-RSA-AES256-SHA256"},	
	{{0x00, 0X68}, "DH-DSS-AES256-SHA256"},	
	{{0x00, 0X39}, "DHE-RSA-AES256-SHA"},	
	{{0x00, 0X38}, "DHE-DSS-AES256-SHA"},	
	{{0x00, 0X37}, "DH-RSA-AES256-SHA"},	
	{{0x00, 0X36}, "DH-DSS-AES256-SHA"},	
	{{0x00, 0X88}, "DHE-RSA-CAMELLIA256-SHA"},	
	{{0x00, 0X87}, "DHE-DSS-CAMELLIA256-SHA"},	
	{{0x00, 0X86}, "DH-RSA-CAMELLIA256-SHA"},	
	{{0x00, 0X85}, "DH-DSS-CAMELLIA256-SHA"},	
	{{0xC0, 0X19}, "AECDH-AES256-SHA"},	
	{{0x00, 0XA7}, "ADH-AES256-GCM-SHA384"},	
	{{0x00, 0X6D}, "ADH-AES256-SHA256"},	
	{{0x00, 0X3A}, "ADH-AES256-SHA"},	
	{{0x00, 0X89}, "ADH-CAMELLIA256-SHA"},	
	{{0xC0, 0X32}, "ECDH-RSA-AES256-GCM-SHA384"},
	{{0xC0, 0X2E}, "ECDH-ECDSA-AES256-GCM-SHA384"},	
	{{0xC0, 0X2A}, "ECDH-RSA-AES256-SHA384"},	
	{{0xC0, 0X26}, "ECDH-ECDSA-AES256-SHA384"},	
	{{0xC0, 0X0F}, "ECDH-RSA-AES256-SHA"},	
	{{0xC0, 0X05}, "ECDH-ECDSA-AES256-SHA"},	
	{{0x00, 0X9D}, "AES256-GCM-SHA384"},	
	{{0x00, 0X3D}, "AES256-SHA256"},	
	{{0x00, 0X35}, "AES256-SHA"},	
	{{0x00, 0X84}, "CAMELLIA256-SHA"},
	{{0x00, 0X8D}, "PSK-AES256-CBC-SHA"},	
	{{0xC0, 0X2F}, "ECDHE-RSA-AES128-GCM-SHA256"},	
	{{0xC0, 0X2B}, "ECDHE-ECDSA-AES128-GCM-SHA256"},	
	{{0xC0, 0X27}, "ECDHE-RSA-AES128-SHA256"},
	{{0xC0, 0X23}, "ECDHE-ECDSA-AES128-SHA256"},	
	{{0xC0, 0X13}, "ECDHE-RSA-AES128-SHA"},	
	{{0xC0, 0X09}, "ECDHE-ECDSA-AES128-SHA"},	
	{{0x00, 0XA4}, "DH-DSS-AES128-GCM-SHA256"},	
	{{0x00, 0XA2}, "DHE-DSS-AES128-GCM-SHA256"},	
	{{0x00, 0XA0}, "DH-RSA-AES128-GCM-SHA256"},	
	{{0x00, 0X9E}, "DHE-RSA-AES128-GCM-SHA256"},
	{{0x00, 0X67}, "DHE-RSA-AES128-SHA256"},
	{{0x00, 0X40}, "DHE-DSS-AES128-SHA256"},
	{{0x00, 0X3F}, "DH-RSA-AES128-SHA256"},	
	{{0x00, 0X3E}, "DH-DSS-AES128-SHA256"},	
	{{0x00, 0X33}, "DHE-RSA-AES128-SHA"},	
	{{0x00, 0X32}, "DHE-DSS-AES128-SHA"},	
	{{0x00, 0X31}, "DH-RSA-AES128-SHA"},	
	{{0x00, 0X30}, "DH-DSS-AES128-SHA"},	
	{{0x00, 0X9A}, "DHE-RSA-SEED-SHA"},	
	{{0x00, 0X99}, "DHE-DSS-SEED-SHA"},	
	{{0x00, 0X98}, "DH-RSA-SEED-SHA"},	
	{{0x00, 0X97}, "DH-DSS-SEED-SHA"},	
	{{0x00, 0X45}, "DHE-RSA-CAMELLIA128-SHA"},	
	{{0x00, 0X44}, "DHE-DSS-CAMELLIA128-SHA"},
	{{0x00, 0X43}, "DH-RSA-CAMELLIA128-SHA"},	
	{{0x00, 0X42}, "DH-DSS-CAMELLIA128-SHA"},	
	{{0xC0, 0X18}, "AECDH-AES128-SHA"},	
	{{0x00, 0XA6}, "ADH-AES128-GCM-SHA256"},	
	{{0x00, 0X6C}, "ADH-AES128-SHA256"},	
	{{0x00, 0X34}, "ADH-AES128-SHA"},	
	{{0x00, 0X9B}, "ADH-SEED-SHA"},	
	{{0x00, 0X46}, "ADH-CAMELLIA128-SHA"},	
	{{0xC0, 0X31}, "ECDH-RSA-AES128-GCM-SHA256"},	
	{{0xC0, 0X2D}, "ECDH-ECDSA-AES128-GCM-SHA256"},
	{{0xC0, 0X29}, "ECDH-RSA-AES128-SHA256"},
	{{0xC0, 0X25}, "ECDH-ECDSA-AES128-SHA256"},
	{{0xC0, 0X0E}, "ECDH-RSA-AES128-SHA"},	
	{{0xC0, 0X04}, "ECDH-ECDSA-AES128-SHA"},	
	{{0x00, 0X9C}, "AES128-GCM-SHA256"},	
	{{0x00, 0X3C}, "AES128-SHA256"},	
	{{0x00, 0X2F}, "AES128-SHA"},
	{{0x00, 0X96}, "SEED-SHA"},	
	{{0x00, 0X41}, "CAMELLIA128-SHA"},	
	{{0x00, 0X8C}, "PSK-AES128-CBC-SHA"},	
	{{0xC0, 0X12}, "ECDHE-RSA-DES-CBC3-SHA"},
	{{0xC0, 0X08}, "ECDHE-ECDSA-DES-CBC3-SHA"},
	{{0x00, 0X16}, "EDH-RSA-DES-CBC3-SHA"},	
	{{0x00, 0X13}, "EDH-DSS-DES-CBC3-SHA"},	
	{{0x00, 0X10}, "DH-RSA-DES-CBC3-SHA"},	
	{{0x00, 0X0D}, "DH-DSS-DES-CBC3-SHA"},	
	{{0xC0, 0X17}, "AECDH-DES-CBC3-SHA"},
	{{0x00, 0X1B}, "ADH-DES-CBC3-SHA"},
	{{0xC0, 0X0D}, "ECDH-RSA-DES-CBC3-SHA"},	
	{{0xC0, 0X03}, "ECDH-ECDSA-DES-CBC3-SHA"},	
	{{0x00, 0X0A}, "DES-CBC3-SHA"},	
	{{0x00, 0X07}, "IDEA-CBC-SHA"},	
	{{0x00, 0X8B}, "PSK-3DES-EDE-CBC-SHA"},	
	{{0x00, 0X21}, "KRB5-IDEA-CBC-SHA"},	
	{{0x00, 0X1F}, "KRB5-DES-CBC3-SHA"},	
	{{0x00, 0X25}, "KRB5-IDEA-CBC-MD5"},	
	{{0x00, 0X23}, "KRB5-DES-CBC3-MD5"},	
	{{0xC0, 0X11}, "ECDHE-RSA-RC4-SHA"},	
	{{0xC0, 0X07}, "ECDHE-ECDSA-RC4-SHA"},
	{{0xC0, 0X16}, "AECDH-RC4-SHA"},
	{{0x00, 0X18}, "ADH-RC4-MD5"},	
	{{0xC0, 0X0C}, "ECDH-RSA-RC4-SHA"},	
	{{0xC0, 0X02}, "ECDH-ECDSA-RC4-SHA"},
	{{0x00, 0X05}, "RC4-SHA"},	
	{{0x00, 0X04}, "RC4-MD5"},	
	{{0x00, 0X8A}, "PSK-RC4-SHA"},	
	{{0x00, 0X20}, "KRB5-RC4-SHA"},	
	{{0x00, 0X24}, "KRB5-RC4-MD5"},	
	{{0xC0, 0X10}, "ECDHE-RSA-NULL-SHA"},
	{{0xC0, 0X06}, "ECDHE-ECDSA-NULL-SHA"},
	{{0xC0, 0X15}, "AECDH-NULL-SHA"},	
	{{0xC0, 0X0B}, "ECDH-RSA-NULL-SHA"},	
	{{0xC0, 0X01}, "ECDH-ECDSA-NULL-SHA"},
	{{0x00, 0X3B}, "NULL-SHA256"},
	{{0x00, 0X02}, "NULL-SHA"},
	{{0x00, 0X01}, "NULL-MD5"},
	{{0x13, 0X01}, "TLS_AES_128_GCM_SHA256"},
	{{0x13, 0X02}, "TLS_AES_256_GCM_SHA384"}, 
	{{0x13, 0X03}, "TLS_CHACHA20_POLY1305_SHA256"},	
	{{0x13, 0X04}, "TLS_AES_128_CCM_SHA256"}, 
	{{0x13, 0X05}, "TLS_AES_128_CCM_8_SHA256"},
	{{0}, NULL},
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

char *fn_pcGetSuite(unsigned char *pucId, int iIdLen, const stSerialString_t *pastElemTypes)
{
    int iLoop = 0;
    int iInLoop = 0;

    if (NULL == pucId || iIdLen < 0 || NULL == pastElemTypes)
    {
        return NULL;
    }

    for  (iLoop = 0; NULL != pastElemTypes[iLoop].pcString; ++iLoop)
    {
        for (iInLoop = 0; iInLoop < iIdLen; ++iInLoop)
        {
            if (pucId[iInLoop] != pastElemTypes[iLoop].aucSerial[iInLoop])
            {
                //continue;
				break;
            }
        }

        if (iInLoop == iIdLen)
        {
            return (char *)(pastElemTypes[iLoop].pcString);
        }
    }

    return NULL;
}

const char* ssl_get_suite_name(unsigned char* suite_value, unsigned short suite_len)
{
	if(suite_value==NULL) return NULL;
	return fn_pcGetSuite((unsigned char *)suite_value, suite_len, (stSerialString_t*)&g_astCipherSuit);
}

const char* ssl_get_version_name(unsigned short version)
{	
	int find_index = -1;
	for(unsigned int i=0;pastSslVersions[i].uiValue!=0;i++)
	{
		if(pastSslVersions[i].uiValue==version)
		{
			find_index = (int)i;
			break;
		}
	}
	return (char*)pastSslVersions[find_index].pcString;
}

int ssl_get_alpn_list(alpn_list_t* alpn_list, int alpn_size, st_ext_t* exts, unsigned short ext_num)
{
	int alpn_ext_len = 0;
	int alpn_proto_len = 0;
	int alpn_proto_num = 0;	
	unsigned char* alpl = NULL;
		
	for(int i=0; i<ext_num; i++)
	{
		if(exts[i].type == ALPN_EXT_TYPE)
		{
			alpn_ext_len = exts[i].len;
			alpl = exts[i].data;
			alpn_ext_len = BtoL2BytesNum((char *)alpl);
			alpl +=2;
			while(alpn_ext_len>0 && alpn_proto_num<alpn_size)
			{
				alpn_proto_len = BtoL1BytesNum((char *)alpl);
				alpl++;
				alpn_ext_len -= 1;
				alpn_list[alpn_proto_num].alpn_len = alpn_proto_len;
				//memcpy(alpn_list[alpn_proto_num].alpn, alpl, alpn_proto_len);
				alpn_list[alpn_proto_num].alpn = (char*)alpl;
				alpn_list[alpn_proto_num].alpn_len = alpn_proto_len;
				alpn_ext_len -= alpn_proto_len;
				alpl += alpn_proto_len;
				alpn_proto_num++;
			}
			break;
		}		
	}
	return alpn_proto_num;
}

UCHAR ssl_doWithVersion(ssl_stream **a_ssl_stream, struct streaminfo *a_tcp,
						unsigned long long region_flag, int thread_seq, void *a_packet)
{	
	UCHAR return_val = SSL_RETURN_NORM;	
	if(!(g_ssl_prog_para.ssl_interested_region_flag&SSL_VERSION))	return return_val;
	
	int find_index = -1;
	unsigned int i=0;
	for(i=0;pastSslVersions[i].uiValue!=0;i++)
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

UCHAR ssl_doWithNewSessionTicket(ssl_stream **a_ssl_stream, struct streaminfo *a_tcp,
										unsigned long long region_flag, int thread_seq, void *a_packet)
{
	UCHAR return_val = SSL_RETURN_NORM;	
	(*a_ssl_stream)->output_region_mask = SSL_NEW_SESSION_TICKET_MASK;
	return_val = ssl_callPlugins(a_ssl_stream, a_tcp, region_flag, thread_seq, a_packet);
	(*a_ssl_stream)->output_region_mask = SSL_INTEREST_KEY_MASK;
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


UCHAR ssl_doWithAlert(ssl_stream **a_ssl_stream, struct streaminfo *a_tcp,
						unsigned long long region_flag, int thread_seq, void *a_packet)
{
	UCHAR return_val = SSL_RETURN_NORM;	
	(*a_ssl_stream)->output_region_mask = SSL_ALERT_MASK;
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
			unsigned char servernamelen = 0;
			pstClientServerName->server_name_list_len =  (*a_ssl_stream)->stClientHello->exts[i].len;
			cur_data =  (*a_ssl_stream)->stClientHello->exts[i].data;
			
			pstClientServerName->server_name_list_len -= sizeof(pstClientServerName->server_name_list_len);
			cur_data += sizeof(pstClientServerName->server_name_list_len);

			/*3=sizeof(pstClientServerName.server_name_type)+sizeof(pstClientServerName.server_name_len)*/
			while(pstClientServerName->server_name_list_len>3)
			{				
				pstClientServerName->server_name_type = BtoL1BytesNum((char *)cur_data);
				pstClientServerName->server_name_len = BtoL2BytesNum((char *)(cur_data+1));
				pstClientServerName->server_name_list_len -= 3;
				cur_data += 3;
				/*have data*/
				if(((pstClientServerName->server_name_type == SERVER_NAME_HOST_TYPE))&&
                            pstClientServerName->server_name_len>0&&
                            pstClientServerName->server_name_list_len>=pstClientServerName->server_name_len)
				{
					pstClientServerName->server_name_data = cur_data;			
					//if(!first_server_name)
					{
						memcpy((*a_ssl_stream)->stClientHello->server_name,
							   pstClientServerName->server_name_data, 
							   pstClientServerName->server_name_len);
						servernamelen = strlen((char*)(*a_ssl_stream)->stClientHello->server_name);
						(*a_ssl_stream)->stClientHello->server_name[servernamelen] = '\0';
						//printf("====servername:%s\n", (*a_ssl_stream)->stClientHello->server_name);						  
                        break;
					}                               
				}
				pstClientServerName->server_name_list_len -= pstClientServerName->server_name_len;
				cur_data += pstClientServerName->server_name_len;				
			}
            if(NULL!=pstClientServerName) 
			{
				dictator_free(thread_seq,pstClientServerName);
			}                        
		}
		else if((*a_ssl_stream)->stClientHello->exts[i].type == SESSION_TICKET_EXT_TYPE)
		{
			(*a_ssl_stream)->stClientHello->session_ticket.ticketlen = (*a_ssl_stream)->stClientHello->exts[i].len;
			(*a_ssl_stream)->stClientHello->session_ticket.ticket =  (*a_ssl_stream)->stClientHello->exts[i].data;
			//printf("====session ticket:%d\n", (*a_ssl_stream)->stClientHello->session_ticket.ticketlen);
		}
		else if((*a_ssl_stream)->stClientHello->exts[i].type == ENCRPTED_SERVER_NAME_EXT_TYPE)
		{			
			char* cur_data = (char*)(*a_ssl_stream)->stClientHello->exts[i].data;	
			int   iUnAnaHelloLen = (*a_ssl_stream)->stClientHello->exts[i].len;
			if(iUnAnaHelloLen>SUITE_VALUELEN)
			{
				(*a_ssl_stream)->stClientHello->encrypted_server_name.suite_value = (unsigned char *)dictator_malloc(thread_seq,SUITE_VALUELEN);
				memcpy((*a_ssl_stream)->stClientHello->encrypted_server_name.suite_value, cur_data, SUITE_VALUELEN);
				cur_data += SUITE_VALUELEN;
				iUnAnaHelloLen -= SUITE_VALUELEN;
			}
			if(iUnAnaHelloLen>KEY_EXCHANGELEN_LEN)
			{
				(*a_ssl_stream)->stClientHello->encrypted_server_name.key_exchange_group = (unsigned short)BtoL2BytesNum(cur_data);
				(*a_ssl_stream)->stClientHello->encrypted_server_name.key_exchange_len = (unsigned short)BtoL2BytesNum(cur_data+2);
				(*a_ssl_stream)->stClientHello->encrypted_server_name.key_exchange = (unsigned char *)dictator_malloc(thread_seq,(*a_ssl_stream)->stClientHello->encrypted_server_name.key_exchange_len);
				memcpy((*a_ssl_stream)->stClientHello->encrypted_server_name.key_exchange, cur_data+KEY_EXCHANGELEN_LEN, (*a_ssl_stream)->stClientHello->encrypted_server_name.key_exchange_len);
				cur_data += (KEY_EXCHANGELEN_LEN+(*a_ssl_stream)->stClientHello->encrypted_server_name.key_exchange_len);
				iUnAnaHelloLen -= (KEY_EXCHANGELEN_LEN+(*a_ssl_stream)->stClientHello->encrypted_server_name.key_exchange_len);
			}
			if(iUnAnaHelloLen>RECORD_DIGESTLEN_LEN)
			{
				(*a_ssl_stream)->stClientHello->encrypted_server_name.record_digest_len= (unsigned short)BtoL2BytesNum(cur_data);				
				(*a_ssl_stream)->stClientHello->encrypted_server_name.record_digest = (unsigned char *)dictator_malloc(thread_seq,(*a_ssl_stream)->stClientHello->encrypted_server_name.record_digest_len);
				memcpy((*a_ssl_stream)->stClientHello->encrypted_server_name.record_digest, cur_data+RECORD_DIGESTLEN_LEN, (*a_ssl_stream)->stClientHello->encrypted_server_name.record_digest_len);
				cur_data += (RECORD_DIGESTLEN_LEN+(*a_ssl_stream)->stClientHello->encrypted_server_name.record_digest_len);
				iUnAnaHelloLen -= (RECORD_DIGESTLEN_LEN+(*a_ssl_stream)->stClientHello->encrypted_server_name.record_digest_len);
			}
			if(iUnAnaHelloLen>ESNILEN_LEN)
			{
				(*a_ssl_stream)->stClientHello->encrypted_server_name.esni_len = (unsigned short)BtoL2BytesNum(cur_data);				
				(*a_ssl_stream)->stClientHello->encrypted_server_name.esni = (unsigned char *)dictator_malloc(thread_seq,(*a_ssl_stream)->stClientHello->encrypted_server_name.esni_len);
				memcpy((*a_ssl_stream)->stClientHello->encrypted_server_name.esni, cur_data+ESNILEN_LEN, (*a_ssl_stream)->stClientHello->encrypted_server_name.esni_len);
				cur_data += (ESNILEN_LEN+(*a_ssl_stream)->stClientHello->encrypted_server_name.esni_len);
				iUnAnaHelloLen -= (ESNILEN_LEN+(*a_ssl_stream)->stClientHello->encrypted_server_name.esni_len);
			}
		}		
	}	
	
	return_val = ssl_callPlugins(a_ssl_stream, a_tcp, region_flag, thread_seq, a_packet);
    (*a_ssl_stream)->output_region_mask = SSL_INTEREST_KEY_MASK;
	return return_val;
}

void print_sni(ssl_stream **a_ssl_stream)
{
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
