/*
 * SSL_Certificate.c

 *
 *  Created on: 2013-5-8
 *      Author: lis
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "SSL_Analyze.h"
#include "ssl.h"
#include "SSL_Message.h"
#include "SSL_Certificate.h"
#include "SSL_Proc.h"

#include "openssl/x509.h"
#include "openssl/objects.h"
#include "openssl/safestack.h"
#include "openssl/cms.h"
#include "openssl/ocsp.h"
#include "openssl/ts.h"
#include "openssl/ts.h"
#include "openssl/x509v3.h"

//debug
#define PRINTF_CERTIFICATE		0

const stValueString_t g_astCertVersions[] =
{
    {   0, "v1" },
    {   1, "v2" },
    {   2, "v3" },
    {   0, NULL },
};

const stSerialString_t g_astAlgrithomTypes[] =
{
    {{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x02}, "md2"},
    {{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x04}, "md4"},
    {{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05}, "md5"},
    {{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01}, "rsaEncryption"},
    {{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x02}, "md2WithRSAEncryption"},
    {{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x03}, "md4WithRSAEncryption"},
    {{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04}, "md5WithRSAEncryption"},
    {{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05}, "shaWithRSAEncryption"},
    {{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x06}, "rsaOAEPEncryptionSET"},
    {{0}, NULL},
};

const stSerialString_t g_astUserItemId[] =
{
    {{0X55, 0X04, 0X03}, "commonName"},
    {{0X55, 0X04, 0x0a}, "organizationName"},
    {{0X55, 0X04, 0x0b}, "organizationalUnitName"},
    {{0X55, 0X04, 0x07}, "localityName"},
    {{0X55, 0X04, 0x06}, "countryName"},    
    {{0X55, 0X1d, 0x11}, "altName"},
    {{0}, NULL},
};

/*return :  1 存在，0 不存在*/
int ssl_read_specific_cert(const char* conj_cert_buf, uint32_t conj_buflen, uint8_t cert_type, char** cert, uint32_t* cert_len)
{
	if(NULL==conj_cert_buf || 0==conj_buflen) return 0;	
	if(CERT_TYPE_INDIVIDUAL!=cert_type && CERT_TYPE_ROOT!=cert_type && CERT_TYPE_MIDDLE!=cert_type && CERT_TYPE_CHAIN!=cert_type) return 0;
	char* 			unproc_cert = (char*)conj_cert_buf;	
	uint32_t		unproc_certlen = conj_buflen;		
	char*			cur_cert = NULL;
	uint32_t		cur_certlen = 0;
	uint32_t		cert_unit_cnt = 0;
	cert_chain_t 	cert_unit[CERT_TYPE_MAXNUM];
	
    while (unproc_certlen > 0)
    {		
    	if(cert_unit_cnt>=CERT_TYPE_MAXNUM)
		{
			break;
		}
		cur_certlen = BtoL3BytesNum(unproc_cert);
		if(cur_certlen+SSL_CERTIFICATE_HDRLEN>unproc_certlen) 
		{
			break;
		}
		cur_cert = unproc_cert+SSL_CERTIFICATE_HDRLEN;	
		if(cert_unit_cnt==0&&CERT_TYPE_INDIVIDUAL==cert_type)
		{
			*cert = cur_cert;
			*cert_len = cur_certlen;
			return 1;
		}
		cert_unit[cert_unit_cnt].cert = cur_cert;
		cert_unit[cert_unit_cnt].cert_len = cur_certlen;		
		cert_unit_cnt++;
        unproc_certlen -= (SSL_CERTIFICATE_HDRLEN+cur_certlen);
		unproc_cert += SSL_CERTIFICATE_HDRLEN+cur_certlen;
	}

	switch(cert_type)
	{
		case CERT_TYPE_ROOT:
			if(cert_unit_cnt>=2)
			{
				*cert = cert_unit[cert_unit_cnt-1].cert;
				*cert_len = cert_unit[cert_unit_cnt-1].cert_len;
				return 1;
			}
			else
			{
				return 0;
			}
			break;
		case CERT_TYPE_MIDDLE:
			if(cert_unit_cnt>=3)
			{
				*cert = cert_unit[1].cert;
				*cert_len = cert_unit[1].cert_len;
				return 1;
			}
			else
			{
				return 0;
			}
			break;
		case CERT_TYPE_CHAIN:
			if(cert_unit_cnt>3)
			{
				*cert = cert_unit[1].cert+cert_unit[1].cert_len;
				*cert_len = conj_buflen-cert_unit[0].cert_len-cert_unit[1].cert_len-cert_unit[cert_unit_cnt-1].cert_len-3*SSL_CERTIFICATE_HDRLEN;
				return 1;
			}
			else
			{
				return 0;
			}
			break;
		default:
			break;
	}	
	return 0;	
}

/*return : chain 个数*/
int ssl_read_all_cert(const char* conj_cert_buf, uint32_t conj_buflen, cert_chain_t* cert_unit, uint32_t unit_size)
{
	if(NULL==conj_cert_buf || 0==conj_buflen) return 0;
	char* 		unproc_cert = (char*)conj_cert_buf;	
	uint32_t	unproc_certlen = conj_buflen;		
	char*		cur_cert = NULL;
	uint32_t	cur_certlen = 0;
	uint32_t	cert_unit_cnt = 0;
	
    while ((int)unproc_certlen > 0)
    {
		if(cert_unit_cnt>=unit_size)
		{
			break;
		}
		cur_certlen = BtoL3BytesNum(unproc_cert);
		if(cur_certlen+SSL_CERTIFICATE_HDRLEN>unproc_certlen) 
		{
			break;
		}
		cur_cert = unproc_cert+SSL_CERTIFICATE_HDRLEN;		
		if(cert_unit_cnt<unit_size)
		{
			cert_unit[cert_unit_cnt].cert = cur_cert;
			cert_unit[cert_unit_cnt].cert_len = cur_certlen;
		}		
		cert_unit_cnt++;
        unproc_certlen -= (SSL_CERTIFICATE_HDRLEN+cur_certlen);
		unproc_cert += SSL_CERTIFICATE_HDRLEN+cur_certlen;
	}
	return cert_unit_cnt;	
}


UCHAR ssl_Certificate(char *pcSslCertificateData, int iDataLen, ssl_stream *a_ssl_stream, struct streaminfo* a_tcp,
		                      unsigned long long region_flag, int thread_seq, void* a_packet)
{
	int iUnAnaCertLen = iDataLen;	
	char *pcCurSslCertificateData = pcSslCertificateData;
	int return_val = 0;
    while (iUnAnaCertLen > 0)
    {
        a_ssl_stream->stSSLCert->certlen = BtoL3BytesNum(pcCurSslCertificateData);        
         if (a_ssl_stream->stSSLCert->certlen + SSL_CERTIFICATE_HDRLEN > iUnAnaCertLen)
        {
        	/**packet trunked is impossible**/
        	break;
        }
        pcCurSslCertificateData += SSL_CERTIFICATE_HDRLEN;
        iUnAnaCertLen -= SSL_CERTIFICATE_HDRLEN;
		a_ssl_stream->p_output_buffer->p_data = pcCurSslCertificateData;
		a_ssl_stream->p_output_buffer->data_size = a_ssl_stream->stSSLCert->certlen;
        a_ssl_stream->output_region_mask = SSL_CERTIFICATE_MASK;
		return_val = ssl_doWithCertificate(&a_ssl_stream, a_tcp, region_flag, thread_seq, a_packet);
		a_ssl_stream->p_output_buffer->p_data = NULL;
		a_ssl_stream->p_output_buffer->data_size = 0;
		if(SSL_RETURN_NORM != return_val)	return return_val;  
		pcCurSslCertificateData += a_ssl_stream->stSSLCert->certlen;
        iUnAnaCertLen -= a_ssl_stream->stSSLCert->certlen; 
    }
	return SSL_RETURN_NORM;
}

void cert_log(ssl_stream *a_ssl_stream)
{
	FILE*           pFile = NULL;
    time_t          currTime;
    struct tm	    *now;
    char		    strTime[32];
    char		    logTime[32];
    char filename[64] = {0};
	time(&currTime);
	now = localtime(&currTime);
	memset(strTime, 0, sizeof(strTime) );
	memset(logTime, 0, sizeof(logTime) );
	strftime(strTime, sizeof(strTime), "%Y-%m-%d %H:%M:%S", now);
	strftime(logTime, sizeof(logTime), "%Y-%m-%d", now);
	strcpy(filename, "./ssl_log/ssl_cert_log_"); 
	strcat(filename, logTime);
	if(((pFile = fopen(filename, "a+"))!=NULL))
	{             
		fprintf(pFile,"%s=SSLIssuer==%s\n",strTime, a_ssl_stream->stSSLCert->SSLIssuer);
		fprintf(pFile,"%s=SSLSub==%s\n",strTime, a_ssl_stream->stSSLCert->SSLSub);
		fclose(pFile); 
	}   
}

UCHAR ssl_AnalyseCertificate(char *pcSslCertificateData, int iDataLen, ssl_stream *a_ssl_stream, struct streaminfo* a_tcp,
		                      unsigned long long region_flag, int thread_seq, void* a_packet)
{
	int iUnAnaCertLen = iDataLen;	
	char *pcCurSslCertificateData = pcSslCertificateData;
	int return_val = 0;
	cert_chain_t cert_unit[CERT_MAXNUM];
	int	cert_num = 0;
	int cert_cnt = ssl_read_all_cert(pcCurSslCertificateData, iUnAnaCertLen, cert_unit, CERT_MAXNUM);
    while (iUnAnaCertLen > 0)
    {
        a_ssl_stream->stSSLCert->certlen = BtoL3BytesNum(pcCurSslCertificateData);        
         if (a_ssl_stream->stSSLCert->certlen + SSL_CERTIFICATE_HDRLEN > iUnAnaCertLen)
        {
        	/**packet trunked is impossible**/
        	break;
        }
        pcCurSslCertificateData += SSL_CERTIFICATE_HDRLEN;
        iUnAnaCertLen -= SSL_CERTIFICATE_HDRLEN;
        return_val = fn_pGetSSLInfo(pcCurSslCertificateData, a_ssl_stream->stSSLCert->certlen, a_ssl_stream, a_tcp, region_flag, thread_seq, a_packet);
        if( SSL_RETURN_NORM != return_val)   	return return_val;

        a_ssl_stream->output_region_mask = SSL_CERTIFICATE_DETAIL_MASK;	
		a_ssl_stream->p_output_buffer->p_data = pcCurSslCertificateData;
		a_ssl_stream->p_output_buffer->data_size = a_ssl_stream->stSSLCert->certlen;
		switch(cert_num)
		{
			case 0:				
				a_ssl_stream->stSSLCert->cert_type = CERT_TYPE_INDIVIDUAL;
				break;
			case 1:
				if(cert_cnt==2)
				{
					a_ssl_stream->stSSLCert->cert_type = CERT_TYPE_ROOT;
				}
				else
				{
					a_ssl_stream->stSSLCert->cert_type = CERT_TYPE_MIDDLE;
				}
				break;
			case 2:
				if(cert_cnt==3)
				{
					a_ssl_stream->stSSLCert->cert_type = CERT_TYPE_ROOT;
				}
				else
				{
					a_ssl_stream->stSSLCert->cert_type = CERT_TYPE_CHAIN;
				}
				break;			
			default:
				if(cert_num==cert_cnt-1)
				{
					a_ssl_stream->stSSLCert->cert_type = CERT_TYPE_ROOT;
				}
				else
				{
					a_ssl_stream->stSSLCert->cert_type = CERT_TYPE_CHAIN;
				}
				break;
		}
        return_val = ssl_doWithCertificateDetail(&a_ssl_stream, a_tcp, region_flag, thread_seq, a_packet);
		a_ssl_stream->p_output_buffer->p_data = NULL;
		a_ssl_stream->p_output_buffer->data_size = 0;
		cert_num++;
		/*释放san内存*/
		if(a_ssl_stream->stSSLCert->SSLSubAltName!=NULL)
		{
			if(a_ssl_stream->stSSLCert->SSLSubAltName->san_array!=NULL)
			{
				dictator_free(thread_seq,a_ssl_stream->stSSLCert->SSLSubAltName->san_array);
				a_ssl_stream->stSSLCert->SSLSubAltName->san_array = NULL;
			}
			dictator_free(thread_seq,a_ssl_stream->stSSLCert->SSLSubAltName);
			a_ssl_stream->stSSLCert->SSLSubAltName = NULL;
		}
		memset(a_ssl_stream->stSSLCert,0,sizeof(st_cert_t)); 
#if PRINTF_CERTIFICATE
		cert_log(); 		
#endif 
		
		if(SSL_RETURN_NORM != return_val && SSL_RETURN_UNNORM != return_val )  	return return_val;      
        pcCurSslCertificateData += a_ssl_stream->stSSLCert->certlen;
        iUnAnaCertLen -= a_ssl_stream->stSSLCert->certlen; 			      
    }
	return SSL_RETURN_NORM;
}


char *fn_pcGetElemType(unsigned char *pucId, int iIdLen, stSerialString_t *pastElemTypes)
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
        iAlgIdLen = strlen((const char *)pastElemTypes[iLoop].aucSerial);
		
        if (iAlgIdLen != iIdLen)
        {
            continue;
        }

        for (iInLoop = 0; iInLoop < iAlgIdLen; ++iInLoop)
        {
            if (pucId[iInLoop] != pastElemTypes[iLoop].aucSerial[iInLoop])
            {
                //continue;
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

UCHAR  fn_pGetSSLInfo_v1(char *pcCert, int iLen, ssl_stream *a_ssl_stream,  struct streaminfo *a_tcp,
		        unsigned long long region_flag, int thread_seq, void *a_packet)

{
    /**variable define and initialise**/
    int iUnAnalyseLen = iLen;
    char *pcCurData  = pcCert;
    char *pcIdString = NULL;
    char *pcCurExtData = NULL;
    char *pcCurElemData = NULL;
    char *pcCurExtItem = NULL;
    char acBuffer[8192] = {0};	
    int iCurExtItemLen = 0;
    int uiLength  = 0;
    int iCurItemLen = 0;
    int iCurElemLen = 0;	
    int iExtenLen = 0;
    int iByteNum = 0;
    int iShowFlag = 0;
    int iLoop = 0;
    st_cert_t *stSSLCert = a_ssl_stream->stSSLCert;
	char* issuer_info = NULL;
	char* sub_info = NULL;

    /**validaty check**/
    if (NULL == pcCert || iLen <= 0 || NULL == stSSLCert)
    {
        //printf("1\n");
    	return SSL_RETURN_UNNORM;
    }

    /**certificate length**/
    uiLength = fn_iSslDecodeTagLength(pcCurData, iUnAnalyseLen, &iByteNum);
    if (uiLength <= 0)
    {
    	//printf("2\n");
    	return SSL_RETURN_UNNORM;
    }

    pcCurData += (iByteNum + 1);
    iUnAnalyseLen -= (iByteNum + 1);
    if (iUnAnalyseLen <= 0)
    {
    //	printf("3\n");
        return SSL_RETURN_UNNORM;
    }

    /***signed certificate***/
    uiLength = fn_iSslDecodeTagLength(pcCurData, iUnAnalyseLen, &iByteNum);
    if (uiLength <= 0)
    {
    //	printf("4\n");
    	return SSL_RETURN_UNNORM;
    }

    pcCurData = pcCurData + iByteNum + 1;
    iUnAnalyseLen -= (iByteNum + 1);
    if (iUnAnalyseLen <= 0)
    {
    //	printf("5\n");
    	return SSL_RETURN_UNNORM;
    }

    /**version**/
    uiLength = fn_iSslDecodeTagLength(pcCurData, iUnAnalyseLen, &iByteNum);
    if (uiLength <= 0)
    {
    //	printf("6\n");
    	return SSL_RETURN_UNNORM;
    }

    pcCurElemData = pcCurData + iByteNum + 1;
    iCurElemLen = uiLength;
    pcCurData += (iByteNum + 1 + uiLength);
    iUnAnalyseLen -= (iByteNum + 1 + uiLength);
    if (iUnAnalyseLen <= 0)
    {
    //	printf("7\n");
    	return SSL_RETURN_UNNORM;
    }

    /*get the version*/
    uiLength = fn_iSslDecodeTagLength(pcCurElemData, iCurElemLen, &iByteNum);
    if (uiLength <= 0)
    {
    //	printf("8\n");
    	return SSL_RETURN_UNNORM;
    }

    iCurElemLen -= (iByteNum + 1);
    if (0 > iCurElemLen)
    {
    //	printf("9\n");
    	return SSL_RETURN_UNNORM;
    }
    pcCurElemData += (iByteNum + 1);

    if ((unsigned char)pcCurElemData[0] < 3)
    {
		unsigned int i = (unsigned int)pcCurElemData[0];
        memcpy(stSSLCert->SSLVersion, g_astCertVersions[i].pcString, 1 + strlen((const char *)g_astCertVersions[i].pcString));
    }

    /**serial number**/
    uiLength = fn_iSslDecodeTagLength(pcCurData, iUnAnalyseLen, &iByteNum);
    if (uiLength <= 0)
    {
    //	printf("10\n");
    	return SSL_RETURN_UNNORM;
    }
    /*find the serial*/
    iUnAnalyseLen -= (iByteNum + 1 + uiLength);
    if (iUnAnalyseLen <= 0)
    {
    //	printf("11\n");
    	return SSL_RETURN_UNNORM;
    }


    for (iLoop = 0; iLoop < (uiLength>=128/3?(128/3-1):uiLength); ++iLoop)
    {
        fn_vPrintNum(stSSLCert->SSLSerialNum+3*iLoop, (unsigned char)pcCurData[iByteNum + 1+iLoop]);
        stSSLCert->SSLSerialNum[3*(1+iLoop)-1] = ' ';
        stSSLCert->SSLSerialNum[3*(1+iLoop)] = '\0';
    }

    //memcpy(stSSLRz->SSLSerialNum, pcCurData+iByteNum + 1, uiLength>=128?127:uiLength);
    //stSSLRz->SSLSerialNum[uiLength>=128?127:uiLength] = '\0';

    pcCurData += (iByteNum + 1 + uiLength);

    /**signature**/
    uiLength = fn_iSslDecodeTagLength(pcCurData, iUnAnalyseLen, &iByteNum);
    if (uiLength <= 0)
    {
    //	printf("12\n");
    	return SSL_RETURN_UNNORM;
    }

    pcCurElemData = pcCurData + iByteNum + 1;
    iCurElemLen = uiLength;
    pcCurData += (iByteNum + 1 + uiLength);
    iUnAnalyseLen -= (iByteNum + 1 + uiLength);
    if (iUnAnalyseLen <= 0)
    {
    //	printf("13\n");
    	return SSL_RETURN_UNNORM;
    }
    /*get the signature info*/
    uiLength = fn_iSslDecodeTagLength(pcCurElemData, iCurElemLen, &iByteNum);
    if (uiLength <= 0)
    {
    //	printf("14\n");
    	return SSL_RETURN_UNNORM;
    }

    iCurElemLen -= (iByteNum + 1);
    if (0 > iCurElemLen)
    {
    //	printf("15\n");
    	return SSL_RETURN_UNNORM;
    }
    pcCurElemData += (iByteNum + 1);

    pcIdString = fn_pcGetElemType((unsigned char *)pcCurElemData, uiLength, (stSerialString_t*)g_astAlgrithomTypes);
    if (NULL != pcIdString)
    {
        memcpy(stSSLCert->SSLAgID, pcIdString, 1 + strlen((const char *)pcIdString));
    }


    /**issuer**/
    uiLength = fn_iSslDecodeTagLength(pcCurData, iUnAnalyseLen, &iByteNum);
    if (uiLength <= 0)
    {
    //	printf("16\n");
    	return SSL_RETURN_UNNORM;
    }
    iUnAnalyseLen -= (iByteNum + 1 + uiLength);
    if (iUnAnalyseLen <= 0)
    {
    //	printf("17\n");
    	return SSL_RETURN_UNNORM;
    }
    pcCurElemData = pcCurData + iByteNum + 1;
    iCurElemLen = uiLength;
    pcCurData += (iByteNum + 1 + uiLength);


    /*get the issuer info*/
    while (iCurElemLen > 0)
    {
        uiLength = fn_iSslDecodeTagLength(pcCurElemData, iCurElemLen, &iByteNum);
        if (uiLength <= 0)
        {
      //  	printf("18\n");
        	return SSL_RETURN_UNNORM;
        }

        iCurElemLen -= (iByteNum + 1);
        if (0 > iCurElemLen)
        {
        //	printf("19\n");
        	return SSL_RETURN_UNNORM;
        }
        pcCurElemData += (iByteNum + 1);

        uiLength = fn_iSslDecodeTagLength(pcCurElemData, iCurElemLen, &iByteNum);
        if (uiLength <= 0)
        {
        //	printf("20\n");
        	return SSL_RETURN_UNNORM;
        }

        iCurElemLen -= (iByteNum + 1);
        if (0 > iCurElemLen)
        {
        //	printf("21\n");
        	return SSL_RETURN_UNNORM;
        }
        pcCurElemData += (iByteNum + 1);

        /*next level:first elem*/
        uiLength = fn_iSslDecodeTagLength(pcCurElemData, iCurElemLen, &iByteNum);
        if (uiLength <= 0)
        {
        //	printf("22\n");
        	return SSL_RETURN_UNNORM;
        }

        iCurElemLen -= (iByteNum + 1 + uiLength);
        if (0 > iCurElemLen)
        {
        //	printf("23\n");
        	return SSL_RETURN_UNNORM;
        }
        pcCurElemData += (iByteNum + 1);
		issuer_info = NULL;
		issuer_info = fn_pcGetElemType((unsigned char *)pcCurElemData, uiLength, (stSerialString_t*)g_astUserItemId);
        if (NULL == issuer_info)
        {
            iShowFlag = 0;
        }
        else
        {
            iShowFlag = 1;			
        }  		
        pcCurElemData += uiLength;
        /*second elem*/
        uiLength = fn_iSslDecodeTagLength(pcCurElemData, iCurElemLen, &iByteNum);
        if (uiLength <= 0)
        {
        //	printf("24\n");
        	return SSL_RETURN_UNNORM;
        }

        iCurElemLen -= (iByteNum + 1);
        if (0 > iCurElemLen)
        {
        //	printf("25\n");
        	return SSL_RETURN_UNNORM;
        }
        pcCurElemData += (iByteNum + 1);

        if (1 == iShowFlag)
        {
			//malformation ssl certificate
			if(uiLength>(int)sizeof(acBuffer))
			{
				return SSL_RETURN_DROPME;
			}
			/*issuer detail*/
			if(0==strncmp(issuer_info, "commonName", strlen("commonName")))
			{
				memcpy(stSSLCert->SSLIssuerCN, pcCurElemData, uiLength >= 64 ? 63 : uiLength);
				stSSLCert->SSLIssuerCN[uiLength >= 64 ? 63 : uiLength] = '\0';
			}
			else if(0==strncmp(issuer_info, "organizationName", strlen("organizationName")))
			{
				memcpy(stSSLCert->SSLIssuerO, pcCurElemData, uiLength >= 64? 63 : uiLength);
				stSSLCert->SSLIssuerO[uiLength >= 64 ? 63 : uiLength] = '\0';
			}
			else if(0==strncmp(issuer_info, "countryName", strlen("countryName")))
			{
				memcpy(stSSLCert->SSLIssuerC, pcCurElemData, uiLength >= 64 ? 63 : uiLength);
				stSSLCert->SSLIssuerC[uiLength >= 64 ? 63 : uiLength] = '\0';
			}
			else
			{
				/*not proc*/
			}			
            memcpy(acBuffer, pcCurElemData, uiLength);
            acBuffer[uiLength] = ';';
            acBuffer[uiLength+1] = '\0';
            memcpy(acBuffer+strlen((const char *)acBuffer), stSSLCert->SSLIssuer, 1 + strlen((const char *)stSSLCert->SSLIssuer));
            iCurItemLen = strlen((const char *)acBuffer);
            memcpy(stSSLCert->SSLIssuer, acBuffer, iCurItemLen >= 512 ? 511 : iCurItemLen);
            stSSLCert->SSLIssuer[ iCurItemLen >= 512 ? 511 : iCurItemLen] = '\0';			
		}

        iCurElemLen -= uiLength;
        pcCurElemData += uiLength;
    }


    /**validaty**/
    uiLength = fn_iSslDecodeTagLength(pcCurData, iUnAnalyseLen, &iByteNum);
    if (uiLength <= 0)
    {
        return SSL_RETURN_UNNORM;
    }
    pcCurElemData = pcCurData + iByteNum + 1;
    iCurElemLen = uiLength;
    pcCurData += (iByteNum + 1 + uiLength);
    iUnAnalyseLen -= (iByteNum + 1 + uiLength);
    if (iUnAnalyseLen <= 0)
    {
        return SSL_RETURN_UNNORM;
    }
    /*get the validaty info*/
    uiLength = fn_iSslDecodeTagLength(pcCurElemData, iCurElemLen, &iByteNum);
    if (uiLength <= 0)
    {
    //	printf("26\n");
    	return SSL_RETURN_UNNORM;
    }

    iCurElemLen -= (iByteNum + 1);
    if (0 > iCurElemLen)
    {
    //	printf("27\n");
    	return SSL_RETURN_UNNORM;
    }
    pcCurElemData += (iByteNum + 1);

    /*utcTime*/
    if (0x0d == uiLength && 0x5a == pcCurElemData[uiLength-1])
    {
	   unsigned int str_len = 0;
       sprintf(stSSLCert->SSLFrom, "%c%c-%c%c-%c%c %c%c:%c%c:%c%c(UTC)", pcCurElemData[0], pcCurElemData[1], pcCurElemData[2], pcCurElemData[3],
                pcCurElemData[4], pcCurElemData[5], pcCurElemData[6], pcCurElemData[7], pcCurElemData[8], pcCurElemData[9], pcCurElemData[10], pcCurElemData[11]);
	   str_len = MIN(strlen(stSSLCert->SSLFrom), (sizeof(stSSLCert->SSLFrom)-1));
	   stSSLCert->SSLFrom[str_len] = '\0';
	}
    //else if (1)
    else
    {
    /*generalizedTime*/
        memcpy(stSSLCert->SSLFrom, pcCurElemData, uiLength>=80?79:uiLength);
        stSSLCert->SSLFrom[uiLength>=80?79:uiLength] = '\0';
    }

    pcCurElemData += uiLength;

    uiLength = fn_iSslDecodeTagLength(pcCurElemData, iCurElemLen, &iByteNum);
    if (uiLength <= 0)
    {
    //	printf("28\n");
    	return SSL_RETURN_UNNORM;
    }

    iCurElemLen -= (iByteNum + 1 - uiLength);
    if (0 > iCurElemLen)
    {
    //	printf("29\n");
    	return SSL_RETURN_UNNORM;
    }
    pcCurElemData += (iByteNum + 1);

    if (0x0d == uiLength && 0x5a == pcCurElemData[uiLength-1])
    {
		unsigned int str_len = 0;
		sprintf(stSSLCert->SSLTo, "%c%c-%c%c-%c%c %c%c:%c%c:%c%c(UTC)", pcCurElemData[0], pcCurElemData[1], pcCurElemData[2], pcCurElemData[3],
                pcCurElemData[4], pcCurElemData[5], pcCurElemData[6], pcCurElemData[7], pcCurElemData[8], pcCurElemData[9], pcCurElemData[10], pcCurElemData[11]);
		str_len = MIN(strlen(stSSLCert->SSLTo), (sizeof(stSSLCert->SSLTo)-1));
		stSSLCert->SSLTo[str_len] = '\0';
    }
//    else if (1)
		else
    {
    /*generalizedTime*/
        memcpy(stSSLCert->SSLTo, pcCurElemData, uiLength>=80?79:uiLength);
        stSSLCert->SSLTo[uiLength>=80?79:uiLength] = '\0';
    }

    /**subject**/
    uiLength = fn_iSslDecodeTagLength(pcCurData, iUnAnalyseLen, &iByteNum);
    if (uiLength <= 0)
    {
    //	printf("30\n");
    	return SSL_RETURN_UNNORM;
    }
    iUnAnalyseLen -= (iByteNum + 1 + uiLength);
    if (iUnAnalyseLen <= 0)
    {
        return SSL_RETURN_UNNORM;
    }
    //memcpy(stSSLRz->SSLSub, pcCurData+iByteNum + 1, uiLength);

    pcCurElemData = pcCurData + (iByteNum + 1);
    iCurElemLen = uiLength;

    pcCurData += (iByteNum + 1 + uiLength);

  /*get the subject info*/
    while (iCurElemLen > 0)
    {
        uiLength = fn_iSslDecodeTagLength(pcCurElemData, iCurElemLen, &iByteNum);
        if (uiLength <= 0)
        {
      //  	printf("31\n");
        	return SSL_RETURN_UNNORM;
        }

        iCurElemLen -= (iByteNum + 1);
        if (0 > iCurElemLen)
        {
        //	printf("32\n");
        	return SSL_RETURN_UNNORM;
        }
        pcCurElemData += (iByteNum + 1);

        uiLength = fn_iSslDecodeTagLength(pcCurElemData, iCurElemLen, &iByteNum);
        if (uiLength <= 0)
        {
        //	printf("33\n");
        	return SSL_RETURN_UNNORM;
        }

        iCurElemLen -= (iByteNum + 1);
        if (0 > iCurElemLen)
        {
        //	printf("34\n");
        	return SSL_RETURN_UNNORM;
        }
        pcCurElemData += (iByteNum + 1);

        /*next level:first elem*/
        uiLength = fn_iSslDecodeTagLength(pcCurElemData, iCurElemLen, &iByteNum);
        if (uiLength <= 0)
        {
        //	printf("35\n");
        	return SSL_RETURN_UNNORM;
        }

        iCurElemLen -= (iByteNum + 1 + uiLength);
        if (0 > iCurElemLen)
        {
        //	printf("36\n");
        	return SSL_RETURN_UNNORM;
        }
        pcCurElemData += (iByteNum + 1);
		sub_info = fn_pcGetElemType((unsigned char *)pcCurElemData, uiLength, (stSerialString_t*)g_astUserItemId);
        if (NULL == sub_info)
        {
            iShowFlag = 0;
        }
        else
        {
            iShowFlag = 1;
        }

        pcCurElemData += uiLength;
        /*second elem*/
        uiLength = fn_iSslDecodeTagLength(pcCurElemData, iCurElemLen, &iByteNum);
        if (uiLength <= 0)
        {
        //	printf("37\n");
        	return SSL_RETURN_UNNORM;
        }

        iCurElemLen -= (iByteNum + 1);
        if (0 > iCurElemLen)
        {
            return SSL_RETURN_UNNORM;
        }
        pcCurElemData += (iByteNum + 1);

        if (1 == iShowFlag)
        {
        //malformation ssl certificate
			if(uiLength>(int)sizeof(acBuffer))
			{
				return SSL_RETURN_DROPME;
			}
			/*sub detail*/
			if(0==strncmp(sub_info, "commonName", strlen("commonName")))
			{
				memcpy(stSSLCert->SSLSubCN, pcCurElemData, uiLength >= 64 ? 63 : uiLength);
				stSSLCert->SSLSubCN[uiLength >= 64 ? 63 : uiLength] = '\0';
			}
			else if(0==strncmp(sub_info, "organizationName", strlen("organizationName")))
			{
				memcpy(stSSLCert->SSLSubO, pcCurElemData, uiLength >= 64? 63 : uiLength);
				stSSLCert->SSLSubO[uiLength >= 64 ? 63 : uiLength] = '\0';
			}
			else if(0==strncmp(sub_info, "countryName", strlen("countryName")))
			{
				memcpy(stSSLCert->SSLSubC, pcCurElemData, uiLength >= 64 ? 63 : uiLength);
				stSSLCert->SSLSubC[uiLength >= 64 ? 63 : uiLength] = '\0';
			}
			else
			{
				/*not proc*/
			}		
            memcpy(acBuffer, pcCurElemData, uiLength);
            acBuffer[uiLength] = ';';
            acBuffer[uiLength+1] = '\0';
            memcpy(acBuffer+strlen((const char *)acBuffer), stSSLCert->SSLSub, 1 + strlen((const char *)stSSLCert->SSLSub));
            iCurItemLen = strlen((const char *)acBuffer);
            memcpy(stSSLCert->SSLSub, acBuffer, iCurItemLen >= 512 ? 511 : iCurItemLen);
            stSSLCert->SSLSub[iCurItemLen >= 512 ? 511 : iCurItemLen ] = '\0';
        }
        iCurElemLen -= uiLength;
        pcCurElemData += uiLength;
    }

	/*add by 20141120*/
	 /**subject public key info**/
    uiLength = fn_iSslDecodeTagLength(pcCurData, iUnAnalyseLen, &iByteNum);
    if (uiLength <= 0)
    {
		return SSL_RETURN_UNNORM;
    }
    pcCurData += (iByteNum + 1 + uiLength);
    iUnAnalyseLen -= (iByteNum + 1 + uiLength);
    if (iUnAnalyseLen <= 0)
    {
		return SSL_RETURN_UNNORM;
    }

    /**extensions**/
    /*level 1: extention items length*/
    iExtenLen = fn_iSslDecodeTagLength(pcCurData, iUnAnalyseLen, &iByteNum);
    if (iExtenLen <= 0)
    {
		return SSL_RETURN_UNNORM;
    }
    pcCurExtData = pcCurData + iByteNum + 1;
    pcCurData += (iByteNum + 1 + iExtenLen);
    iUnAnalyseLen -= (iByteNum + 1 + iExtenLen);
    if (iUnAnalyseLen < 0)
    {
		return SSL_RETURN_UNNORM;
    }

    /*level 2: extention items*/
    iExtenLen = fn_iSslDecodeTagLength(pcCurExtData, iExtenLen, &iByteNum);
    if (iExtenLen <= 0)
    {
		return SSL_RETURN_UNNORM;
    }
    pcCurExtData += (iByteNum + 1);

    while (iExtenLen > 0)
    {
        /*current item length*/
        iCurExtItemLen = fn_iSslDecodeTagLength(pcCurExtData, iExtenLen, &iByteNum);
        if (iCurExtItemLen <= 0)
        {
        	return SSL_RETURN_UNNORM;
        }

        pcCurExtItem = pcCurExtData + iByteNum + 1;
        pcCurExtData += (iByteNum + 1 + iCurExtItemLen);
        iExtenLen -= (iByteNum + 1 + iCurExtItemLen);
        if (iExtenLen < 0)
        {
        	return SSL_RETURN_UNNORM;
        }

        /*extention item id length*/
        uiLength = fn_iSslDecodeTagLength(pcCurExtItem, iCurExtItemLen, &iByteNum);
        if (uiLength <= 0)
        {
        	return SSL_RETURN_UNNORM;
        }
        pcCurExtItem += (iByteNum + 1);
        iCurExtItemLen -= (iByteNum + 1);

        /*alter subject id*/
        if (3 == uiLength && 0x55 == pcCurExtItem[0] && 0x1d == pcCurExtItem[1] && 0x11 == pcCurExtItem[2])
        {
            /*subject alter name*/
            pcCurExtItem += uiLength;
            iCurExtItemLen -= uiLength;
            uiLength = fn_iSslDecodeTagLength(pcCurExtItem, iCurExtItemLen, &iByteNum);
            if (uiLength <= 0)
            {
				return SSL_RETURN_UNNORM;
            }
            pcCurExtItem += (iByteNum + 1);
            iCurExtItemLen -= (iByteNum + 1);
            if (iCurExtItemLen < 0)
            {
				return SSL_RETURN_UNNORM;
            } 
			uiLength = fn_iSslDecodeTagLength(pcCurExtItem, iCurExtItemLen, &iByteNum);
            if (uiLength <= 0)
            {
				return SSL_RETURN_UNNORM;
            }
            pcCurExtItem += (iByteNum + 1);
            iCurExtItemLen -= (iByteNum + 1);
            if (iCurExtItemLen < 0)
            {
				return SSL_RETURN_UNNORM;
            }
			/*get the last piece*/
            pcCurElemData = pcCurExtItem;
            iCurElemLen = uiLength; 
			pcCurExtItem += uiLength;
            iCurExtItemLen -= uiLength;			
			/*DNS name*/
			if((char)0x82 == pcCurElemData[0])
			{
				/*SAN:subject alter name*/				
				uiLength = fn_iSslDecodeTagLength(pcCurElemData, iCurElemLen, &iByteNum);
				if (uiLength <= 0)
				{
					return SSL_RETURN_UNNORM;
				} 
				pcCurElemData += (iByteNum + 1);
	            iCurElemLen -= (iByteNum + 1 + uiLength);
	            if (iCurElemLen < 0)
	            {
					return SSL_RETURN_UNNORM;
	            }
				//memcpy(stSSLCert->SSLSubBak, pcCurElemData, uiLength>=512?511:uiLength);
           		//stSSLCert->SSLSubBak[uiLength>=512?511:uiLength] = '\0';					
				pcCurElemData += uiLength;
			}				
        }
    }

    /**algorithm identifier**/
    uiLength = fn_iSslDecodeTagLength(pcCurData, iUnAnalyseLen, &iByteNum);
    if (uiLength <= 0)
    {
		return SSL_RETURN_UNNORM;
    }
    pcCurExtData = pcCurData + iByteNum + 1;
    iExtenLen = uiLength;
    pcCurData += (iByteNum + 1 + uiLength);
    iUnAnalyseLen -= (iByteNum + 1 + uiLength);
    if (iUnAnalyseLen <= 0)
    {
		return SSL_RETURN_UNNORM;
    }

    uiLength = fn_iSslDecodeTagLength(pcCurExtData, iExtenLen, &iByteNum);
    if (uiLength <= 0)
    {
		return SSL_RETURN_UNNORM;
    }

    iExtenLen -= (iByteNum + 1);
    if (0 > iExtenLen)
    {
		return SSL_RETURN_UNNORM;
    }
    pcCurExtData += (iByteNum + 1);

    pcIdString = fn_pcGetElemType((unsigned char *)pcCurExtData, uiLength, (stSerialString_t*)g_astAlgrithomTypes);
    if (NULL != pcIdString)
    {
            memcpy(stSSLCert->SSLFPAg, pcIdString, 1 + strlen((const char *)pcIdString));
    }

    pcCurExtData += uiLength;
    /**padding**/
    /**encrypted**/
	
    return SSL_RETURN_NORM;
}

UCHAR  fn_pGetSSLInfo(char *pcCert, int iLen, ssl_stream *a_ssl_stream,  struct streaminfo *a_tcp,
		        			unsigned long long region_flag, int thread_seq, void *a_packet)
{	
	//return SSL_RETURN_NORM;
	int data = 0;
	
	X509 *x509_handle = d2i_X509(NULL, (unsigned char const **)&pcCert, iLen);
	if (x509_handle == NULL) 
	{
		return SSL_RETURN_NORM;
	}
	
	if(NULL!=x509_handle->cert_info)
	{
		/*version*/
		int ver = X509_get_version(x509_handle);		
		memcpy(a_ssl_stream->stSSLCert->SSLVersion, 
				g_astCertVersions[ver].pcString, 
				1 + strlen((const char *)g_astCertVersions[ver].pcString));

		/*serial num*/
		if(NULL!=x509_handle->cert_info->serialNumber)
		{
			memcpy(a_ssl_stream->stSSLCert->SSLSerialNum, 
					x509_handle->cert_info->serialNumber->data, 
					x509_handle->cert_info->serialNumber->length);
		}		

		/*SSL AgID*/		
		ASN1_OBJECT* salg  = x509_handle->cert_info->signature->algorithm;
		OBJ_obj2txt(a_ssl_stream->stSSLCert->SSLAgID, sizeof(a_ssl_stream->stSSLCert->SSLAgID), salg, 1);

		/*SSL Issuer*/
		X509_NAME* issuer = X509_get_issuer_name(x509_handle);
		if(NULL!=issuer)
		{
			X509_NAME_get_text_by_NID(issuer, NID_commonName, a_ssl_stream->stSSLCert->SSLIssuerCN, sizeof(a_ssl_stream->stSSLCert->SSLIssuerCN));
			X509_NAME_get_text_by_NID(issuer, NID_organizationName, a_ssl_stream->stSSLCert->SSLIssuerO, sizeof(a_ssl_stream->stSSLCert->SSLIssuerO));
			X509_NAME_get_text_by_NID(issuer, NID_countryName, a_ssl_stream->stSSLCert->SSLIssuerC, sizeof(a_ssl_stream->stSSLCert->SSLIssuerC));

			snprintf(a_ssl_stream->stSSLCert->SSLIssuer,
					 sizeof(a_ssl_stream->stSSLCert->SSLIssuer),
					 "%s;%s;%s",
					 a_ssl_stream->stSSLCert->SSLIssuerCN,
					 a_ssl_stream->stSSLCert->SSLIssuerO,
					 a_ssl_stream->stSSLCert->SSLIssuerC);
		}

		/*SSL Subject*/
		X509_NAME* subject = X509_get_subject_name(x509_handle);
		if(NULL!=subject)
		{
			X509_NAME_get_text_by_NID(subject, NID_commonName, a_ssl_stream->stSSLCert->SSLSubCN, sizeof(a_ssl_stream->stSSLCert->SSLSubCN));
			X509_NAME_get_text_by_NID(subject, NID_organizationName, a_ssl_stream->stSSLCert->SSLSubO, sizeof(a_ssl_stream->stSSLCert->SSLSubO));
			X509_NAME_get_text_by_NID(subject, NID_countryName, a_ssl_stream->stSSLCert->SSLSubC, sizeof(a_ssl_stream->stSSLCert->SSLSubC));

			snprintf(a_ssl_stream->stSSLCert->SSLSub,
								 sizeof(a_ssl_stream->stSSLCert->SSLSub),
								 "%s;%s;%s",
								 a_ssl_stream->stSSLCert->SSLSubCN,
								 a_ssl_stream->stSSLCert->SSLSubO,
								 a_ssl_stream->stSSLCert->SSLSubC);
		}
		
		/*validity*/
		ASN1_TIME *start = X509_get_notBefore(x509_handle);
		ASN1_TIME *end = X509_get_notAfter(x509_handle);
		sprintf(a_ssl_stream->stSSLCert->SSLFrom, "%s", start->data);
		sprintf(a_ssl_stream->stSSLCert->SSLTo, "%s", end->data);				

		/*subject bak*/	
		GENERAL_NAMES* subjectAltNames = (GENERAL_NAMES*)X509_get_ext_d2i(x509_handle, NID_subject_alt_name, NULL, NULL);  
		if(!subjectAltNames) return SSL_RETURN_NORM;
		int cnt = sk_GENERAL_NAME_num(subjectAltNames);
		char* san = NULL;
		ASN1_STRING *san_name;
		int len = 0;
		GENERAL_NAME* generalName;
		if(cnt>0)
		{			
			a_ssl_stream->stSSLCert->SSLSubAltName = (st_san_t*)dictator_malloc(thread_seq, sizeof(st_san_t));
			a_ssl_stream->stSSLCert->SSLSubAltName->san_array = (san_t*)dictator_malloc(thread_seq, cnt*sizeof(san_t));
			memset(a_ssl_stream->stSSLCert->SSLSubAltName->san_array,0,cnt*sizeof(san_t));
			a_ssl_stream->stSSLCert->SSLSubAltName->count = 0;
			for (int i = 0; i < cnt; i++)
			{       
				generalName = sk_GENERAL_NAME_value(subjectAltNames, i);
				if(!generalName) return SSL_RETURN_NORM;
				if(GEN_DNS == generalName->type)
				{
					san_name = (ASN1_STRING*)GENERAL_NAME_get0_value(generalName, NULL);
					if(ASN1_STRING_length(san_name)>0)
					{
						san = (char*)ASN1_STRING_data(san_name);
						snprintf(a_ssl_stream->stSSLCert->SSLSubAltName->san_array[a_ssl_stream->stSSLCert->SSLSubAltName->count].san,
								 sizeof(a_ssl_stream->stSSLCert->SSLSubAltName->san_array[a_ssl_stream->stSSLCert->SSLSubAltName->count].san),
								 "%s",
								 san);						
						a_ssl_stream->stSSLCert->SSLSubAltName->count++;
					}	
				}			
			}
		}
		if(subjectAltNames)
		{
			GENERAL_NAMES_free(subjectAltNames);
		}
	}	
	return SSL_RETURN_NORM;
}

