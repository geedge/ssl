 
#include "SSL_Analyze.h"
#include "ssl.h"
#include "SSL_Message.h"
#include "SSL_Proc.h"
#include "SSL_Common.h"
#include "SSL_Certificate.h"

extern ssl_prog_runtime_parameter_t 	g_ssl_prog_para;

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

const stSerialString_t g_astCompression[] =
{
    {{0}, NULL},
};

char *fn_pcGetSuite(unsigned char *pucId, int iIdLen, stSerialString_t *pastElemTypes)
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


const char* ssl_get_suite(st_suites_t* ciphersuits)
{
	if(ciphersuits==NULL) return NULL;
	return fn_pcGetSuite((unsigned char *)ciphersuits->suite_value, ciphersuits->suite_len, (stSerialString_t*)g_astCipherSuit);
}

unsigned short ssl_getHelloVersion(unsigned char *pcData, unsigned int iDataLen)
{    
    if (CLIENT_HELLO != pcData[0] && SERVER_HELLO != pcData[0])
    {
        return 0;
    }

    if (03 == pcData[4] && 1 == pcData[5])
    {
        /*TLS 1.0*/
        return 0x0301;
    }
    else if (03 == pcData[4] && 2 == pcData[5])
    {
        /*TLS 2.0*/
        return 0x0302;
    }
	else if (03 == pcData[4] && 3 == pcData[5])
    {
        /*TLS 2.0*/
        return 0x0303;
    }
    else if (03 == pcData[4] && 0 == pcData[5])
    {
        /*SSL 3.0*/
        return 0x0300;
    }
    else if (0 == pcData[4] && 2 == pcData[5])
    {
        /*SSL 2.0*/
        return 0x0002;
    }
    else if (0xfe == (unsigned char)pcData[4] && 0xff == (unsigned char)pcData[5])
    {
        /*DTLS 1.0*/
        return 0xfeff;
    }
    else if (0x01 == (unsigned char)pcData[4] && 0x00 == (unsigned char)pcData[5])
    {
        /*DTLS 1.0 (OpenSSL pre 0.9.8f)*/
        return 0x0100;
    }
    return 0;
}



int fn_iIsHandShakeMsg(unsigned char ucMsgType)
{
    switch (ucMsgType)
    {
//        case HELLO_REQUEST:
            case CLIENT_HELLO:
	     case SERVER_HELLO:
            case CERTIFICATE:
//        case SERVER_KEY_EXCHANGE:
//        case CERTIFICATE_REQUEST:
//        case SERVER_HELLO_DONE:
//        case CERTIFICATE_VERIFY:
//        case CLIENT_KEY_EXCHANGE:
//        case FINISHED:
            return 1;
        break;
        default:
            return 0;
        break;
    }
}

/*
Function: analyse ssl hand shake msgs
Note:       if one msg is trunked, just wait
return : SSL_RETURN_UNNORM : error ; SSL_RETURN_DROPME/KILLME; business return_value
*/
UCHAR ssl_analyseHandShake(char *pcSslData,  int iAllMsgLen,  int iSslUnAnalyseLen, int * res, ssl_stream *a_ssl_stream, struct streaminfo* a_tcp,
		                      unsigned long long region_flag, int thread_seq, void* a_packet)
{
    /**variable define and initialise**/	
    int 					iSslDataLen 		= 0;
	char*					pcCurSslData 		= pcSslData;
    int 					iUnAnalyseLen 		= 0;   
    int 					iUnAnaCertLen 		= 0;
	int 					iUnAnaHelloLen 		= 0;
    UCHAR 					return_val 			= SSL_RETURN_NORM;  
	stHandShakeTypeHdr_t* 	pstHandShakeTypeHdr = (stHandShakeTypeHdr_t *)pcSslData;

	iSslDataLen 		= iAllMsgLen < iSslUnAnalyseLen ? iAllMsgLen : iSslUnAnalyseLen;
	iUnAnalyseLen 		= iAllMsgLen < iSslUnAnalyseLen ? iAllMsgLen : iSslUnAnalyseLen;   
    
	while (iUnAnalyseLen > 0)
	{		
	
		//20150324 
		pstHandShakeTypeHdr = (stHandShakeTypeHdr_t *)pcSslData;
		pcCurSslData 		= pcSslData;
		/**analyse certification**/		
		if (CERTIFICATE == pstHandShakeTypeHdr->ucContType)
		{
			if(iUnAnalyseLen<CERTIFICATE_HDRLEN)
			{
			    /**packet trunked**/
				break;
			}
			
			if(a_ssl_stream->stSSLCert==NULL)
			{
				a_ssl_stream->stSSLCert = (st_cert_t*)dictator_malloc(thread_seq,sizeof(st_cert_t));
				//memset(a_ssl_stream->stSSLCert, 0, sizeof(a_ssl_stream->stSSLCert));
			}			
			memset(a_ssl_stream->stSSLCert,0,sizeof(st_cert_t));	
			a_ssl_stream->stSSLCert->totallen = BtoL3BytesNum((char *)(pcCurSslData + 4));
			if(a_ssl_stream->stSSLCert->totallen<0)  return SSL_RETURN_DROPME;

			/*7 means cert_type+len*/
			if (a_ssl_stream->stSSLCert->totallen + 7> iUnAnalyseLen)
			{
				/**packet trunked**/
				break;
			}
			
			/*2 means version*/				
			pcCurSslData += CERTIFICATE_HDRLEN;
			iUnAnaCertLen = iUnAnalyseLen-CERTIFICATE_HDRLEN;
			
			if(g_ssl_prog_para.ssl_interested_region_flag&SSL_CERTIFICATE)
			{				
				a_ssl_stream->p_output_buffer->p_data = pcCurSslData;
				a_ssl_stream->p_output_buffer->data_size = iUnAnaCertLen;				
				a_ssl_stream->output_region_mask = SSL_CERTIFICATE_MASK;
				return_val = ssl_doWithCertificate(&a_ssl_stream, a_tcp, region_flag, thread_seq, a_packet);
				a_ssl_stream->p_output_buffer->p_data = NULL;
				a_ssl_stream->p_output_buffer->data_size = 0;
				if(SSL_RETURN_NORM != return_val)	return return_val;
			}			
			if(g_ssl_prog_para.ssl_interested_region_flag&SSL_CERTIFICATE_DETAIL)
			{									
				return_val = ssl_AnalyseCertificate(pcCurSslData,iUnAnaCertLen, a_ssl_stream, a_tcp,region_flag,thread_seq, a_packet);
				if(SSL_RETURN_NORM != return_val)	return return_val;
			}
			iUnAnalyseLen -= (a_ssl_stream->stSSLCert->totallen +7);			
			pcSslData += (a_ssl_stream->stSSLCert->totallen +7);
		}
		/**analyse client_hello**/
		else if (CLIENT_HELLO == pstHandShakeTypeHdr->ucContType)
		{
			if(iUnAnalyseLen<CLIENT_HELLO_HDRLEN)
			{
				break;
			}
			if(a_ssl_stream->stClientHello==NULL)
			{
				a_ssl_stream->stClientHello = (st_client_hello_t*)dictator_malloc(thread_seq,sizeof(st_client_hello_t));
				memset(a_ssl_stream->stClientHello, 0, sizeof(a_ssl_stream->stClientHello));
				ssl_initStructClientHello(a_ssl_stream->stClientHello);
			}
			
			a_ssl_stream->stClientHello->totallen = BtoL3BytesNum((char *)(pcCurSslData + 1));			
			if(a_ssl_stream->stClientHello->totallen<0)  return SSL_RETURN_DROPME;
			
			/*4 means client_type+len*/
			if (a_ssl_stream->stClientHello->totallen+CLIENT_HELLO_HDRLEN > iUnAnalyseLen)
			{
				/**packet trunked**/
				break;
			}				
			if(0==(a_ssl_stream->stClientHello->client_ver = ssl_getHelloVersion((unsigned char*)pcCurSslData, iUnAnalyseLen)))
			{
				return SSL_RETURN_DROPME;
			}
			
			iUnAnaHelloLen = a_ssl_stream->stClientHello->totallen-sizeof(a_ssl_stream->stClientHello->client_ver);	
			if(iUnAnaHelloLen<0)
			{
				return SSL_RETURN_DROPME;
			}
			pcCurSslData += CLIENT_HELLO_HDRLEN+sizeof(a_ssl_stream->stClientHello->client_ver);				
			
			/*get client hello random*/
			a_ssl_stream->stClientHello->random.gmt_time = (unsigned int)BtoL4BytesNum(pcCurSslData);
			pcCurSslData += sizeof(a_ssl_stream->stClientHello->random.gmt_time);
			iUnAnaHelloLen -= sizeof(a_ssl_stream->stClientHello->random.gmt_time);
			if(iUnAnaHelloLen<0)
			{
				return SSL_RETURN_DROPME;
			}
			memcpy(a_ssl_stream->stClientHello->random.random_bytes, pcCurSslData, sizeof(a_ssl_stream->stClientHello->random.random_bytes));
			pcCurSslData += sizeof(a_ssl_stream->stClientHello->random.random_bytes);
			iUnAnaHelloLen -= sizeof(a_ssl_stream->stClientHello->random.random_bytes);
			if(iUnAnaHelloLen<0)
			{
				return SSL_RETURN_DROPME;
			}

			/*get client hello session*/
			a_ssl_stream->stClientHello->session.session_len = (unsigned char)BtoL1BytesNum(pcCurSslData);
			pcCurSslData += sizeof(a_ssl_stream->stClientHello->session.session_len);
			iUnAnaHelloLen -= sizeof(a_ssl_stream->stClientHello->session.session_len);
			if(iUnAnaHelloLen<0)
			{
				return SSL_RETURN_DROPME;
			}
			if(a_ssl_stream->stClientHello->session.session_len>iUnAnaHelloLen)
			{
				return SSL_RETURN_DROPME;
			}
			if(a_ssl_stream->stClientHello->session.session_len!=0)
			{
				a_ssl_stream->stClientHello->session.session_value = (unsigned char *)dictator_malloc(thread_seq,a_ssl_stream->stClientHello->session.session_len);
				memcpy(a_ssl_stream->stClientHello->session.session_value, pcCurSslData, a_ssl_stream->stClientHello->session.session_len);
				pcCurSslData += a_ssl_stream->stClientHello->session.session_len;
				iUnAnaHelloLen -= a_ssl_stream->stClientHello->session.session_len;
				if(iUnAnaHelloLen<0)
				{
					return SSL_RETURN_DROPME;
				}
			}

			/*get client hello suites*/
			a_ssl_stream->stClientHello->ciphersuits.suite_len = (unsigned short)BtoL2BytesNum(pcCurSslData);
			pcCurSslData += sizeof(a_ssl_stream->stClientHello->ciphersuits.suite_len);
			iUnAnaHelloLen -= sizeof(a_ssl_stream->stClientHello->ciphersuits.suite_len);
			if(iUnAnaHelloLen<0)
			{
				return SSL_RETURN_DROPME;
			}
			if(a_ssl_stream->stClientHello->ciphersuits.suite_len>iUnAnaHelloLen)
			{
				return SSL_RETURN_DROPME;
			}
			if(a_ssl_stream->stClientHello->ciphersuits.suite_len!=0)
			{
				a_ssl_stream->stClientHello->ciphersuits.suite_value = (unsigned char *)dictator_malloc(thread_seq,a_ssl_stream->stClientHello->ciphersuits.suite_len);
				memcpy(a_ssl_stream->stClientHello->ciphersuits.suite_value, pcCurSslData, a_ssl_stream->stClientHello->ciphersuits.suite_len);
				pcCurSslData += a_ssl_stream->stClientHello->ciphersuits.suite_len;
				iUnAnaHelloLen -= a_ssl_stream->stClientHello->ciphersuits.suite_len;
				if(iUnAnaHelloLen<0)
				{
					return SSL_RETURN_DROPME;
				}
			}			

			/*get client hello compress*/
			a_ssl_stream->stClientHello->com_method.methlen = (unsigned short)BtoL1BytesNum(pcCurSslData);
			pcCurSslData += sizeof(a_ssl_stream->stClientHello->com_method.methlen);
			iUnAnaHelloLen -= sizeof(a_ssl_stream->stClientHello->com_method.methlen);
			if(iUnAnaHelloLen<0)
			{
				return SSL_RETURN_DROPME;
			}
			if(a_ssl_stream->stClientHello->com_method.methlen>iUnAnaHelloLen)
			{
				return SSL_RETURN_DROPME;
			}
			if(a_ssl_stream->stClientHello->com_method.methlen!=0)
			{
				a_ssl_stream->stClientHello->com_method.methods = (unsigned char *)dictator_malloc(thread_seq,a_ssl_stream->stClientHello->com_method.methlen);
				memcpy(a_ssl_stream->stClientHello->com_method.methods, pcCurSslData, a_ssl_stream->stClientHello->com_method.methlen);
				pcCurSslData += a_ssl_stream->stClientHello->com_method.methlen;
				iUnAnaHelloLen -= a_ssl_stream->stClientHello->com_method.methlen;
				if(iUnAnaHelloLen<0)
				{
					return SSL_RETURN_DROPME;
				}
			}

			/*get extension*/
			a_ssl_stream->stClientHello->extlen = (unsigned short)BtoL2BytesNum(pcCurSslData);
			pcCurSslData += sizeof(a_ssl_stream->stClientHello->extlen);
			
			int i=0;
			for(i=0; iUnAnaHelloLen>=4 && i<MAX_EXTENSION_NUM; i++)//min len of ext is 4 byte
			{
				a_ssl_stream->stClientHello->exts[i].type = (unsigned short)BtoL2BytesNum(pcCurSslData);
				pcCurSslData += sizeof(a_ssl_stream->stClientHello->exts[i].type);
				iUnAnaHelloLen -= sizeof(a_ssl_stream->stClientHello->exts[i].type);
				if(iUnAnaHelloLen<0)
				{
					return SSL_RETURN_DROPME;
				}
				
				a_ssl_stream->stClientHello->exts[i].len = (unsigned short)BtoL2BytesNum(pcCurSslData);
				pcCurSslData += sizeof(a_ssl_stream->stClientHello->exts[i].len);
				iUnAnaHelloLen -= sizeof(a_ssl_stream->stClientHello->exts[i].len);
				if(iUnAnaHelloLen<0)
				{
					return SSL_RETURN_DROPME;
				}

				memcpy(a_ssl_stream->stClientHello->exts[i].data,
					   pcCurSslData, 
					   MIN(a_ssl_stream->stClientHello->exts[i].len, MAX_EXT_DATA_LEN));	//get ext data

				pcCurSslData += a_ssl_stream->stClientHello->exts[i].len;
				iUnAnaHelloLen -= a_ssl_stream->stClientHello->exts[i].len;
				if(iUnAnaHelloLen<0)
				{
					return SSL_RETURN_DROPME;
				}
			}
			a_ssl_stream->stClientHello->ext_num = i;
			return_val = ssl_doWithClientHello(&a_ssl_stream, a_tcp, region_flag, thread_seq, a_packet);
			//20141121
			if(a_ssl_stream->stClientHello->session.session_value!=NULL)
			{
				dictator_free(thread_seq,a_ssl_stream->stClientHello->session.session_value);
				a_ssl_stream->stClientHello->session.session_value = NULL;
			}
			if(a_ssl_stream->stClientHello->ciphersuits.suite_value!=NULL)
			{
				dictator_free(thread_seq,a_ssl_stream->stClientHello->ciphersuits.suite_value);
				a_ssl_stream->stClientHello->ciphersuits.suite_value = NULL;
			}
			if(a_ssl_stream->stClientHello->com_method.methods!=NULL)
			{
				dictator_free(thread_seq,a_ssl_stream->stClientHello->com_method.methods);
				a_ssl_stream->stClientHello->com_method.methods = NULL;
			}
			
			if(SSL_RETURN_NORM != return_val)	return return_val;
			iUnAnalyseLen -= (a_ssl_stream->stClientHello->totallen + CLIENT_HELLO_HDRLEN);			
			pcSslData += (a_ssl_stream->stClientHello->totallen + CLIENT_HELLO_HDRLEN);
		}

         /**analyse server_hello**/
		 else if (SERVER_HELLO == pstHandShakeTypeHdr->ucContType)
		 {
		 	if(iUnAnalyseLen<SERVER_HELLO_HDRLEN)
			{
				break;
			}		
			if(a_ssl_stream->stServerHello==NULL)
			{
				a_ssl_stream->stServerHello = (st_server_hello_t*)dictator_malloc(thread_seq,sizeof(st_server_hello_t));
				memset(a_ssl_stream->stServerHello, 0, sizeof(a_ssl_stream->stServerHello));	
				ssl_initStructServerHello(a_ssl_stream->stServerHello);
			}
			a_ssl_stream->stServerHello->totallen = BtoL3BytesNum((char *)(pcCurSslData + 1));			
			if(a_ssl_stream->stServerHello->totallen<0)  return SSL_RETURN_DROPME;
			
			/*4 means client_type+len*/
			if (a_ssl_stream->stServerHello->totallen+SERVER_HELLO_HDRLEN > iUnAnalyseLen)
			{
				/**packet trunked**/
				break;
			}				
			if(0==(a_ssl_stream->stServerHello->client_ver = ssl_getHelloVersion((unsigned char*)pcCurSslData, iUnAnalyseLen)))
			{
				return SSL_RETURN_DROPME;
			}
			
			iUnAnaHelloLen = a_ssl_stream->stServerHello->totallen-sizeof(a_ssl_stream->stServerHello->client_ver);			
			if(iUnAnaHelloLen<0)
			{
				return SSL_RETURN_DROPME;
			}

			pcCurSslData += SERVER_HELLO_HDRLEN+sizeof(a_ssl_stream->stServerHello->client_ver);					
			
			/*get server hello random*/
			a_ssl_stream->stServerHello->random.gmt_time = (unsigned int)BtoL4BytesNum(pcCurSslData);
			pcCurSslData += sizeof(a_ssl_stream->stServerHello->random.gmt_time);
			iUnAnaHelloLen -= sizeof(a_ssl_stream->stServerHello->random.gmt_time);
			if(iUnAnaHelloLen<0)
			{
				return SSL_RETURN_DROPME;
			}
			memcpy(a_ssl_stream->stServerHello->random.random_bytes, pcCurSslData, sizeof(a_ssl_stream->stServerHello->random.random_bytes));
			pcCurSslData += sizeof(a_ssl_stream->stServerHello->random.random_bytes);
			iUnAnaHelloLen -= sizeof(a_ssl_stream->stServerHello->random.random_bytes);
			if(iUnAnaHelloLen<0)
			{
				return SSL_RETURN_DROPME;
			}

			/*get server hello session*/
			a_ssl_stream->stServerHello->session.session_len = (unsigned char)BtoL1BytesNum(pcCurSslData);
			pcCurSslData += sizeof(a_ssl_stream->stServerHello->session.session_len);
			iUnAnaHelloLen -= sizeof(a_ssl_stream->stServerHello->session.session_len);
			if(iUnAnaHelloLen<0)
			{
				return SSL_RETURN_DROPME;
			}
			if(a_ssl_stream->stServerHello->session.session_len>iUnAnaHelloLen)
			{
				return SSL_RETURN_DROPME;
			}
			if(a_ssl_stream->stServerHello->session.session_len!=0)
			{
				a_ssl_stream->stServerHello->session.session_value = (unsigned char *)dictator_malloc(thread_seq,a_ssl_stream->stServerHello->session.session_len);
				memcpy(a_ssl_stream->stServerHello->session.session_value, pcCurSslData, a_ssl_stream->stServerHello->session.session_len);
				pcCurSslData += a_ssl_stream->stServerHello->session.session_len;
				iUnAnaHelloLen -= a_ssl_stream->stServerHello->session.session_len;
				if(iUnAnaHelloLen<0)
				{
					return SSL_RETURN_DROPME;
				}
			}

			/*get server hello suites*/
			a_ssl_stream->stServerHello->ciphersuits.suite_len = 2;
			a_ssl_stream->stServerHello->ciphersuits.suite_value = (unsigned char *)dictator_malloc(thread_seq,a_ssl_stream->stServerHello->ciphersuits.suite_len);
			memcpy(a_ssl_stream->stServerHello->ciphersuits.suite_value, pcCurSslData, a_ssl_stream->stServerHello->ciphersuits.suite_len);
			pcCurSslData += a_ssl_stream->stServerHello->ciphersuits.suite_len;
			iUnAnaHelloLen -= a_ssl_stream->stServerHello->ciphersuits.suite_len;	
			if(iUnAnaHelloLen<0)
			{
				return SSL_RETURN_DROPME;
			}				

			/*get server hello compress*/
			/*
			a_ssl_stream->stServerHello->com_method.methlen = (unsigned short)BtoL1BytesNum(pcCurSslData);
			pcCurSslData += sizeof(a_ssl_stream->stServerHello->com_method.methlen);
			iUnAnaHelloLen -= sizeof(a_ssl_stream->stServerHello->com_method.methlen);
			if(iUnAnaHelloLen<0)
			{
				return SSL_RETURN_DROPME;
			}
			*/
			/*20160906 methlen只占一个字节*/
			a_ssl_stream->stServerHello->com_method.methlen = 1;
			if(a_ssl_stream->stServerHello->com_method.methlen!=0)
			{
				a_ssl_stream->stServerHello->com_method.methods = (unsigned char *)dictator_malloc(thread_seq,a_ssl_stream->stServerHello->com_method.methlen);
				memcpy(a_ssl_stream->stServerHello->com_method.methods, pcCurSslData, a_ssl_stream->stServerHello->com_method.methlen);
				pcCurSslData += a_ssl_stream->stServerHello->com_method.methlen;
				iUnAnaHelloLen -= a_ssl_stream->stServerHello->com_method.methlen;
				if(iUnAnaHelloLen<0)
				{
					return SSL_RETURN_DROPME;
				}
			}	
			return_val = ssl_doWithServerHello(&a_ssl_stream, a_tcp, region_flag, thread_seq, a_packet);
			//20141121
			if(a_ssl_stream->stServerHello->session.session_value!=NULL)
			{
				dictator_free(thread_seq,a_ssl_stream->stServerHello->session.session_value);
				a_ssl_stream->stServerHello->session.session_value = NULL;
			}
			if(a_ssl_stream->stServerHello->ciphersuits.suite_value!=NULL)
			{
				dictator_free(thread_seq,a_ssl_stream->stServerHello->ciphersuits.suite_value);
				a_ssl_stream->stServerHello->ciphersuits.suite_value = NULL;
			}
			if(a_ssl_stream->stServerHello->com_method.methods!=NULL)
			{
				dictator_free(thread_seq,a_ssl_stream->stServerHello->com_method.methods);
				a_ssl_stream->stServerHello->com_method.methods = NULL;
			}
			if(SSL_RETURN_NORM != return_val)	return return_val;
			iUnAnalyseLen -= (a_ssl_stream->stServerHello->totallen + SERVER_HELLO_HDRLEN);	
			pcSslData += (a_ssl_stream->stServerHello->totallen + SERVER_HELLO_HDRLEN);			
		}	
		 else
		 {
			break;
		 }
	}

    *res =  (iSslDataLen - iUnAnalyseLen);
    return SSL_RETURN_NORM;
}

UCHAR ssl_analyseAppData(char *pcSslData,  int iAllMsgLen,  int iSslUnAnalyseLen, int *res, ssl_stream *a_ssl_stream, struct streaminfo* a_tcp,
		                      unsigned long long region_flag, int thread_seq, void* a_packet)
{
    /**variable define and initialise**/
    int 			return_val 		= SSL_RETURN_NORM;
    int 	iUnAnalyseLen 	= iAllMsgLen < iSslUnAnalyseLen ? iAllMsgLen : iSslUnAnalyseLen;
 
    /**validaty check**/
    if (NULL == pcSslData || iUnAnalyseLen <= 0)
    {
    	*res = 0;
    	return SSL_RETURN_NORM;
    }
	a_ssl_stream->output_region_mask = SSL_APPLICATION_DATA_MASK;
	a_ssl_stream->p_output_buffer->p_data = pcSslData;
	a_ssl_stream->p_output_buffer->data_size = iUnAnalyseLen;
	return_val = ssl_doWithApplicationData(&a_ssl_stream, a_tcp, region_flag, thread_seq, a_packet);	
	a_ssl_stream->p_output_buffer->p_data = NULL;
	a_ssl_stream->p_output_buffer->data_size = 0;
	*res = iUnAnalyseLen;
	if(SSL_RETURN_NORM!= return_val)  return return_val;	
	return SSL_RETURN_NORM;
}


char *fn_pcGetType(unsigned char *pucId, int iIdLen, stSerialString_t *pastElemTypes)
{
    int iLoop = 0;
    int iInLoop = 0;
    int iAlgIdLen = 0;

    if (NULL == pucId || iIdLen < 0 || NULL == pastElemTypes)
    {
        return NULL;
    }

    for  (iLoop = 0; NULL != pastElemTypes[iLoop].pcString; ++iLoop)
    {
        iAlgIdLen = iIdLen ;

        for (iInLoop = 0; iInLoop < iAlgIdLen; ++iInLoop)
        {
            if (pucId[iInLoop] != pastElemTypes[iLoop].aucSerial[iInLoop])
            {
                break;
            }
        }
        if (iInLoop == iAlgIdLen)
        {
            return (char *)(pastElemTypes[iLoop].pcString);
        }
    }

    return NULL;
}

int ssl_protoRecg(char *pcData, int iDataLen)
{
    if (NULL == pcData || iDataLen < 1)
    {
        return 0;
    }
    else if (20 > pcData[0] || 23 < pcData[0])
    {
        return 0;
    }

    if (03 == pcData[1] && 1 == pcData[2])
    {
        /*TLS 1.0*/
        return 0x0301;
    }
    else if (03 == pcData[1] && 2 == pcData[2])
    {
        /*TLS 2.0*/
        return 0x0302;
    }
	else if (03 == pcData[1] && 3 == pcData[2])
    {
        /*TLS 3.0*/
        return 0x0303;
    }
    else if (03 == pcData[1] && 0 == pcData[2])
    {
        /*SSL 3.0*/
        return 0x0300;
    }
    else if (0 == pcData[1] && 2 == pcData[2])
    {
        /*SSL 2.0*/
        return 0x0002;
    }
    else if (0xfe == (unsigned char)pcData[1] && 0xff == (unsigned char)pcData[2])
    {
        /*DTLS 1.0*/
        return 0xfeff;
    }
    else if (0x01 == (unsigned char)pcData[1] && 0x00 == (unsigned char)pcData[2])
    {
        /*DTLS 1.0 (OpenSSL pre 0.9.8f)*/
        return 0x0100;
    }

    return 0;
}
#define MAX_THREAD_NUM 64
#define COUNTER_NUM 4096

extern volatile unsigned long long g_SysInputInfo[MAX_THREAD_NUM][COUNTER_NUM];

UCHAR ssl_analyseStreamData(char *pcSslData, int iDataLen, int *res, ssl_stream *a_ssl_stream, struct streaminfo* a_tcp,
		                     		unsigned long long region_flag, int thread_seq, void* a_packet)
{
    /**variable define and initialise**/
    stSSLRecordHdr_t*    	pstSSLRecordHdr 	= NULL;
    stHandShakeTypeHdr_t*	pstHandShakeTypeHdr = NULL; 
    int 					iUnAnalyseLen 		= iDataLen;
    char*					pcCurSslData 		= pcSslData;
    int 					iCurAllMsgLen 		= 0;
    int 					iCurMsgLen 			= 0;	
    int 					is_trunk 			= 0;	
    UCHAR 					return_val 			= SSL_RETURN_NORM;

    /**validaty check**/
    if (NULL == pcSslData || iDataLen < SSL_HEADER_LEN)
    {
    	*res = 0;
    	return SSL_RETURN_NORM;
    }

    /**first packet of an hand shake conversation**/
    if (UNKNOWN_VERSION == a_ssl_stream->uiSslVersion)
    {
        a_ssl_stream->uiSslVersion = (unsigned int)ssl_protoRecg(pcSslData, iDataLen);
        if (UNKNOWN_VERSION == a_ssl_stream->uiSslVersion)
        {
        	*res = -1;
        	return SSL_RETURN_DROPME;
        }
		/*version callback*/
		return_val = ssl_doWithVersion(&a_ssl_stream, a_tcp, region_flag, thread_seq, a_packet);			
		if(SSL_RETURN_NORM!= return_val)  return return_val;			
    }
    while (iUnAnalyseLen > 0)
    {
        if (SSL_HANDSHAKE_MSG_TRUNKED == a_ssl_stream->uiMsgState)
        {
        	switch(a_ssl_stream->ucContType)
        	{
        	case HANDSHAKE:        		
        	case APPLICATION_DATA:
        		pstHandShakeTypeHdr = (stHandShakeTypeHdr_t *)pcCurSslData;
        		iCurAllMsgLen = (a_ssl_stream->uiAllMsgLen - a_ssl_stream->uiMsgProcLen) ;
        		iCurMsgLen = (a_ssl_stream->uiAllMsgLen - a_ssl_stream->uiMsgProcLen) < iUnAnalyseLen ? (a_ssl_stream->uiAllMsgLen - a_ssl_stream->uiMsgProcLen) : iUnAnalyseLen;
        		a_ssl_stream->uiMsgState = SSL_HANDSHAKE_NOTRUNK;
        		break;
        	 default:
        		 a_ssl_stream->uiMsgState = SSL_HANDSHAKE_NOTRUNK;
        		 a_ssl_stream->ucContType = 0;
        		 *res = -1;
        		 return SSL_RETURN_NORM;
        	}
        }
        else 
        {
        	
            pstSSLRecordHdr = (stSSLRecordHdr_t *)pcCurSslData;
            switch(pstSSLRecordHdr->ucContType)
            {             
            case HANDSHAKE:
            	a_ssl_stream->ucContType = HANDSHAKE;
				a_ssl_stream->is_ssl_stream = SSL_TRUE;
            	a_ssl_stream->uiAllMsgLen = htons(pstSSLRecordHdr->usTotalLen);
            	pstHandShakeTypeHdr = (stHandShakeTypeHdr_t *)(pcCurSslData + SSL_RECORD_HDRLEN);
            	pcCurSslData += SSL_RECORD_HDRLEN;
            	iUnAnalyseLen -= SSL_RECORD_HDRLEN;
            	iCurAllMsgLen = a_ssl_stream->uiAllMsgLen;
            	iCurMsgLen = a_ssl_stream->uiAllMsgLen < iUnAnalyseLen ? a_ssl_stream->uiAllMsgLen : iUnAnalyseLen;
            	a_ssl_stream->uiMsgState = SSL_HANDSHAKE_NOTRUNK;				
            	break;

            case APPLICATION_DATA:				
            	a_ssl_stream->ucContType = APPLICATION_DATA;
				a_ssl_stream->is_ssl_stream = SSL_TRUE;
            	a_ssl_stream->uiAllMsgLen = htons(pstSSLRecordHdr->usTotalLen);
              	iCurAllMsgLen = a_ssl_stream->uiAllMsgLen ;
				iUnAnalyseLen -= SSL_RECORD_HDRLEN;
            	iCurMsgLen = a_ssl_stream->uiAllMsgLen < iUnAnalyseLen ? a_ssl_stream->uiAllMsgLen : iUnAnalyseLen;
            	a_ssl_stream->uiMsgState = SSL_HANDSHAKE_NOTRUNK;	
				//static int count;
				//count++;
				//printf("%d\t%d\t%lld\n",count, a_ssl_stream->uiAllMsgLen, g_SysInputInfo[0][0]);							
				break;

			case CHANGE_CIPHER_SEP:
				a_ssl_stream->ucContType = CHANGE_CIPHER_SEP;
				a_ssl_stream->is_ssl_stream = SSL_TRUE;
				a_ssl_stream->uiAllMsgLen = htons(pstSSLRecordHdr->usTotalLen);
              	iCurAllMsgLen = a_ssl_stream->uiAllMsgLen ;
				iUnAnalyseLen -= SSL_RECORD_HDRLEN;
            	iCurMsgLen = a_ssl_stream->uiAllMsgLen < iUnAnalyseLen ? a_ssl_stream->uiAllMsgLen : iUnAnalyseLen;
            	a_ssl_stream->uiMsgState = SSL_HANDSHAKE_NOTRUNK;            	
            	*res = iCurAllMsgLen;
            	break;
				
			case ALERT:				
				a_ssl_stream->ucContType = ALERT;
				a_ssl_stream->is_ssl_stream = SSL_TRUE;
				a_ssl_stream->uiAllMsgLen = htons(pstSSLRecordHdr->usTotalLen);
              	iCurAllMsgLen = a_ssl_stream->uiAllMsgLen ;
				iUnAnalyseLen -= SSL_RECORD_HDRLEN;
            	iCurMsgLen = a_ssl_stream->uiAllMsgLen < iUnAnalyseLen ? a_ssl_stream->uiAllMsgLen : iUnAnalyseLen;
            	a_ssl_stream->uiMsgState = SSL_HANDSHAKE_NOTRUNK;            	
            	*res = iCurAllMsgLen;            
				break;

            default:
				if(a_ssl_stream->is_ssl_stream == SSL_TRUE)
				{
					a_ssl_stream->uiMsgState = SSL_HANDSHAKE_NOTRUNK;
					a_ssl_stream->ucContType = 0;
					*res = -1;
					return SSL_RETURN_NORM;
				}
            	else 
				{
					a_ssl_stream->uiMsgState = SSL_HANDSHAKE_NOTRUNK;
					a_ssl_stream->ucContType = 0;
					*res = -1;
					return SSL_RETURN_DROPME;
				}
            }
        }
		switch(a_ssl_stream->ucContType)
		{
			case APPLICATION_DATA:				
				/*不缓冲数据，实时处理*/
				return_val = ssl_analyseAppData((char *)pcCurSslData + SSL_RECORD_HDRLEN, iCurAllMsgLen, iUnAnalyseLen, res, a_ssl_stream, a_tcp, region_flag, thread_seq, a_packet);
				/*the data is not enough*/
				if(*res < iCurAllMsgLen)
				{
					is_trunk = 1;
				}				
				break;			

			/*other handshark proto not process*/
			case HANDSHAKE:
				/*缓冲够数据再处理*/
				if (fn_iIsHandShakeMsg(*(unsigned char *)pstHandShakeTypeHdr))
				{
					/*res表示处理的数据*/
					return_val = ssl_analyseHandShake((char *)pstHandShakeTypeHdr, iCurAllMsgLen, iUnAnalyseLen, res, a_ssl_stream, a_tcp, region_flag, thread_seq, a_packet);
					if(*res < iCurAllMsgLen)
					{
						is_trunk = 1;
					}
				}
				else
				{					
					if(iCurMsgLen>=iCurAllMsgLen)
					{
						/*本消息处理完成*/
						*res = iCurMsgLen;
					}					
					else
					{
						/*表示需要缓存当前数据包的所有数据，所以*res被处理的数据为0*/
						*res = 0;
						is_trunk = 1;
					}					
				}
				/*20140731 res<0 but no why*/
		        if(*res<0)
		        {
		                return SSL_RETURN_DROPME;
		        }				
				break;

			default :
				*res = iCurMsgLen;
				break;
		}	

		/*the data is not enough*/
		if(is_trunk)
		//if(*res < iCurMsgLen)
		{
			a_ssl_stream->uiMsgState = SSL_HANDSHAKE_MSG_TRUNKED;
			a_ssl_stream->uiMsgProcLen += *res;
			iUnAnalyseLen -= *res ;
			break;
		}
		else
		{
			/*本次消息处理完成*/
			a_ssl_stream->uiAllMsgLen = 0;
			a_ssl_stream->uiMsgProcLen = 0;
		}		
        if (SSL_RETURN_NORM != return_val)
        {
            return return_val;
        } 	        
        pcCurSslData += *res;
        iUnAnalyseLen -= *res;	
    }

	*res = iDataLen - iUnAnalyseLen;
    return SSL_RETURN_NORM;
}

UCHAR ssl_analyseStream(struct streaminfo *a_tcp, void** pme, int thread_seq, void *a_packet)
{
	/**variables define, and initialise**/
	int 				return_val 			= APP_STATE_GIVEME;
	ssl_stream* 		a_ssl_stream 		= (ssl_stream *)*pme;	
    struct tcpdetail*	tcp_detail 			= (struct tcpdetail*)a_tcp->pdetail;
    char* 				pcSslData 			= NULL;
    int 		        iSslDateLen 		= 0;
    int 				iRet 				= 0;

    if(NULL== a_ssl_stream)
    {
		return SSL_RETURN_DROPME;
    }	
	
    if(0==tcp_detail->datalen)
	{
		/*trans ssl over state*/
		if(a_ssl_stream->over_flag == SSL_TRUE&&a_ssl_stream->uiSslVersion!=UNKNOWN_VERSION)
		{
			return ssl_callPlugins(&a_ssl_stream, a_tcp, a_ssl_stream->output_region_flag, thread_seq, a_packet);
		}
		else  return APP_STATE_GIVEME;
	}    	   

	/**if buffered, copy new data to the buff**/
    /**if lose packets, drop the buffered data**/
    /*bad data fill the buffer,  or lose pkt clear it*/
    if ((tcp_detail->lostlen > 0) || (a_ssl_stream->uiMaxBuffLen>0 && a_ssl_stream->uiCurBuffLen  >= a_ssl_stream->uiMaxBuffLen))
    {
    	//20151231
    	return SSL_RETURN_DROPME;
    	a_ssl_stream->uiCurBuffLen = 0;
    }

    if (a_ssl_stream->uiCurBuffLen > 0)
    {
        //20151231 not enough,tcp_detail->pdata will be cut, it's not useful
        if(a_ssl_stream->uiMaxBuffLen - a_ssl_stream->uiCurBuffLen < (int)tcp_detail->datalen)
        {
			return SSL_RETURN_DROPME;
		}
    	iSslDateLen = MIN((int)tcp_detail->datalen,(a_ssl_stream->uiMaxBuffLen - a_ssl_stream->uiCurBuffLen));
		
    	memcpy(a_ssl_stream->pcSslBuffer + a_ssl_stream->uiCurBuffLen, tcp_detail->pdata, iSslDateLen);
    	a_ssl_stream->uiCurBuffLen += iSslDateLen;
    	iSslDateLen = a_ssl_stream->uiCurBuffLen;
    	pcSslData = a_ssl_stream->pcSslBuffer;
    }
    else
    {
    	pcSslData = (char*)tcp_detail->pdata;
    	iSslDateLen = tcp_detail->datalen;
    }

	
    return_val = ssl_analyseStreamData(pcSslData, iSslDateLen, &iRet, a_ssl_stream,  a_tcp, a_ssl_stream->output_region_flag, thread_seq, a_packet);

	if(SSL_RETURN_NORM != return_val)
    {
    	return return_val;
    }
    /*is ssl_stream, need buffer data*/
    if (iRet < 0)
    {
    	a_ssl_stream->uiCurBuffLen = 0;
    }
    else if (iRet >= iSslDateLen)
    {
    	a_ssl_stream->uiCurBuffLen = 0;
    }
    else
    {
    	if(0==a_ssl_stream->uiMaxBuffLen)
    	{
    		a_ssl_stream->pcSslBuffer = (char*)dictator_malloc(thread_seq, MAX_DATA_BUFFER);
			a_ssl_stream->uiMaxBuffLen = MAX_DATA_BUFFER;
		}
    	fn_vMemCpy(a_ssl_stream->pcSslBuffer, (int)a_ssl_stream->uiMaxBuffLen, pcSslData + iRet, (int)(iSslDateLen - iRet));
	    a_ssl_stream->uiCurBuffLen = iSslDateLen - iRet;
    }
    return return_val;
}


