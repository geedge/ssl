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

/*
const struct ssl_serial_string g_astCipherSuit[] =
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

struct ssl_serial_string g_astCipherSuit[] =
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



int BtoL4BytesNum(const char *pcData)
{
    int uiLength = 0;
    uiLength = pcData[0];
    uiLength = (uiLength << 8) + (unsigned char)pcData[1];
    uiLength = (uiLength << 8) + (unsigned char)pcData[2];
	uiLength = (uiLength << 8) + (unsigned char)pcData[3];
    return uiLength;
}

int BtoL3BytesNum(const char *pcData)
{
    int uiLength = 0;
    uiLength = pcData[0];
    uiLength = (uiLength << 8) + (unsigned char)pcData[1];
    uiLength = (uiLength << 8) + (unsigned char)pcData[2];

    return uiLength;
}

int BtoL2BytesNum(const char *pcData)
{
    int uiLength = 0;
    uiLength = pcData[0];
    uiLength = (uiLength << 8) + (unsigned char)pcData[1];

    return uiLength;
}

int BtoL1BytesNum(const char *pcData)
{
    int uiLength = 0;
    uiLength = pcData[0];

    return uiLength;
}

char *fn_pcGetSuite(const unsigned char *pucId, int iIdLen, const struct ssl_serial_string *pastElemTypes)
{
    int iLoop;
    int iInLoop;

    if (NULL == pucId || iIdLen < 0 || NULL == pastElemTypes)
    {
        return NULL;
    }

    for  (iLoop = 0; NULL != pastElemTypes[iLoop].string; ++iLoop)
    {
        for (iInLoop = 0; iInLoop < iIdLen; ++iInLoop)
        {
            if (pucId[iInLoop] != pastElemTypes[iLoop].serial[iInLoop])
            {
                //continue;
				break;
            }
        }

        if (iInLoop == iIdLen)
        {
            return (char *)(pastElemTypes[iLoop].string);
        }
    }

    return NULL;
}

const char* ssl_get_suite_name(unsigned char* suite_value, unsigned short suite_len)
{
	if(suite_value==NULL) return NULL;
	return fn_pcGetSuite((unsigned char *)suite_value, suite_len, (struct ssl_serial_string*)&g_astCipherSuit);
}

int ssl_get_link_state(struct ssl_runtime_context *ssl_context)
{
	UCHAR state = 0;
	if(SSL_FALSE==ssl_context->link_state)
	{
		if(SSL_TRUE==ssl_context->over_flag)
			state = SESSION_STATE_CLOSE | SESSION_STATE_PENDING;
		else
			state = SESSION_STATE_PENDING;
	}
	else
	{
		if(SSL_TRUE==ssl_context->over_flag)
		{
			state = SESSION_STATE_CLOSE;
		}
		else
		{
			state = SESSION_STATE_DATA;
		}
	}
	
	ssl_context->link_state = SSL_TRUE;

	return state;
}

void ssl_call_plugins(const struct streaminfo *a_tcp, struct ssl_runtime_context *ssl_context, char *buff, int buff_len, enum ssl_interested_region output_region_mask, int thread_seq, const void *a_packet)
{	
	stSessionInfo session_info;
	unsigned long long region_flag = (g_ssl_runtime_para.ssl_interested_region_flag >> output_region_mask) % 2;
	
	if(SSL_TRUE==region_flag || ssl_context->over_flag==SSL_TRUE )
	{
		if (PROT_STATE_DROPME != ssl_context->business.return_value)
		{		
			session_info.plugid = g_ssl_runtime_para.ssl_plugid;
			session_info.prot_flag = (((unsigned long long)1)<<output_region_mask);
			session_info.session_state = ssl_get_link_state(ssl_context);
			session_info.app_info =  (void*)(&ssl_context->stream);
			session_info.buf=buff;
			session_info.buflen=buff_len;
			ssl_context->business.return_value=PROT_PROCESS(&session_info, &(ssl_context->business.param), thread_seq, (struct streaminfo *)a_tcp, a_packet);
			ssl_context->is_call_business=1;
		}
	}
}
