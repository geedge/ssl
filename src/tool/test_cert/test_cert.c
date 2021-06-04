
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>


#include "openssl/x509.h"
#include "openssl/objects.h"
#include "openssl/safestack.h"
#include "openssl/cms.h"
#include "openssl/ocsp.h"
#include "openssl/ts.h"
#include "openssl/ts.h"
#include "openssl/x509v3.h"

#define SSL_RETURN_NORM 				0x53
#define SSL_RETURN_UNNORM 				0x54
#define SSL_RETURN_RESET_BUFFER			0x55
#define SSL_RETURN_DROPME 				0x57


/*ssl_read_all_cert中的结构体*/
typedef struct cert_chain_s
{
     char* 						cert;
	 uint32_t					cert_len;
}cert_chain_t;

typedef struct _san_t
{
	char 					san[64]; 
}san_t;

typedef struct _st_san_t
{
	int 					count;
	san_t* 					san_array; 					//指针数组
}st_san_t;

typedef struct _st_cert_t
{
	int 					totallen;
	int 					certlen;
	char 					SSLVersion[10];   
	char 					SSLSerialNum[128];
	char 					SSLAgID [64];     
	char 					SSLIssuer[512];  	
	char 					SSLSub[512];    
	char 					SSLFrom[80];     
	char 					SSLTo[80];     
	char 					SSLFPAg[32];  	 	
	char 					SSLIssuerC[64]; //country  	
	char 					SSLIssuerO[64]; //organize
	char 					SSLIssuerCN[64];//cname	
	char 					SSLSubC[64]; //country  	
	char 					SSLSubO[64]; //organize
	char 					SSLSubCN[64];//cname		
	st_san_t* 				SSLSubAltName;  
	uint8_t 				cert_type;	
}st_cert_t;

int BtoL3BytesNum(char *pcData)
{
    int uiLength = 0;
    uiLength = pcData[0];
    uiLength = (uiLength << 8) + (unsigned char)pcData[1];
    uiLength = (uiLength << 8) + (unsigned char)pcData[2];

    return uiLength;
}

int BtoL4BytesNum(char *pcData)
{
    int uiLength = 0;
    uiLength = pcData[0];
    uiLength = (uiLength << 8) + (unsigned char)pcData[1];
    uiLength = (uiLength << 8) + (unsigned char)pcData[2];
	uiLength = (uiLength << 8) + (unsigned char)pcData[3];

    return uiLength;
}


typedef struct _stValueString_t
{
    unsigned int 			uiValue;
    const char 				*pcString;
}stValueString_t;

#define CERT_VER_MAXNUM			3
const stValueString_t g_astCertVersions[] =
{
    {   0, "v1" },
    {   1, "v2" },
    {   2, "v3" },    
    {   3, "v4" },
    {   0, NULL },
};

char  fn_pGetSSLInfo(char *pcCert, int iLen, st_cert_t*	stSSLCert)
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
		if(ver>CERT_VER_MAXNUM) goto cert_return;
		memcpy(stSSLCert->SSLVersion, 
				g_astCertVersions[ver].pcString, 
				1 + strlen((const char *)g_astCertVersions[ver].pcString));

		/*serial num*/
		if(NULL!=x509_handle->cert_info->serialNumber)
		{
			memcpy(stSSLCert->SSLSerialNum, 
					x509_handle->cert_info->serialNumber->data, 
					x509_handle->cert_info->serialNumber->length);
		}		

		/*SSL AgID*/		
		ASN1_OBJECT* salg  = x509_handle->cert_info->signature->algorithm;
		OBJ_obj2txt(stSSLCert->SSLAgID, sizeof(stSSLCert->SSLAgID), salg, 1);

		/*SSL Issuer*/
		X509_NAME* issuer = X509_get_issuer_name(x509_handle);
		if(NULL!=issuer)
		{
			X509_NAME_get_text_by_NID(issuer, NID_commonName, stSSLCert->SSLIssuerCN, sizeof(stSSLCert->SSLIssuerCN));
			X509_NAME_get_text_by_NID(issuer, NID_organizationName, stSSLCert->SSLIssuerO, sizeof(stSSLCert->SSLIssuerO));
			X509_NAME_get_text_by_NID(issuer, NID_countryName, stSSLCert->SSLIssuerC, sizeof(stSSLCert->SSLIssuerC));

			snprintf(stSSLCert->SSLIssuer,
					 sizeof(stSSLCert->SSLIssuer),
					 "%s;%s;%s",
					 stSSLCert->SSLIssuerCN,
					 stSSLCert->SSLIssuerO,
					 stSSLCert->SSLIssuerC);
		}

		/*SSL Subject*/
		X509_NAME* subject = X509_get_subject_name(x509_handle);
		if(NULL!=subject)
		{
			X509_NAME_get_text_by_NID(subject, NID_commonName, stSSLCert->SSLSubCN, sizeof(stSSLCert->SSLSubCN));
			X509_NAME_get_text_by_NID(subject, NID_organizationName, stSSLCert->SSLSubO, sizeof(stSSLCert->SSLSubO));
			X509_NAME_get_text_by_NID(subject, NID_countryName, stSSLCert->SSLSubC, sizeof(stSSLCert->SSLSubC));

			snprintf(stSSLCert->SSLSub,
					 sizeof(stSSLCert->SSLSub),
					 "%s;%s;%s",
					 stSSLCert->SSLSubCN,
					 stSSLCert->SSLSubO,
					 stSSLCert->SSLSubC);
		}
		
		/*validity*/
		ASN1_TIME *start = X509_get_notBefore(x509_handle);
		ASN1_TIME *end = X509_get_notAfter(x509_handle);
		sprintf(stSSLCert->SSLFrom, "%s", start->data);
		sprintf(stSSLCert->SSLTo, "%s", end->data);				

		/*subject bak*/	
		GENERAL_NAMES* subjectAltNames = (GENERAL_NAMES*)X509_get_ext_d2i(x509_handle, NID_subject_alt_name, NULL, NULL);  
		if(!subjectAltNames) goto cert_return;
		int cnt = sk_GENERAL_NAME_num(subjectAltNames);
		char* san = NULL;
		ASN1_STRING *san_name;
		int len = 0;
		GENERAL_NAME* generalName;
		if(cnt>0)
		{			
			stSSLCert->SSLSubAltName = (st_san_t*)malloc(sizeof(st_san_t));
			stSSLCert->SSLSubAltName->san_array = (san_t*)malloc(cnt*sizeof(san_t));
			memset(stSSLCert->SSLSubAltName->san_array,0,cnt*sizeof(san_t));
			stSSLCert->SSLSubAltName->count = 0;
			int i = 0;
			for (i = 0; i < cnt; i++)
			{       
				generalName = sk_GENERAL_NAME_value(subjectAltNames, i);
				if(!generalName) goto cert_return;
				if(GEN_DNS == generalName->type)
				{
					san_name = (ASN1_STRING*)GENERAL_NAME_get0_value(generalName, NULL);
					if(ASN1_STRING_length(san_name)>0)
					{
						san = (char*)ASN1_STRING_data(san_name);
						snprintf(stSSLCert->SSLSubAltName->san_array[stSSLCert->SSLSubAltName->count].san,
								 sizeof(stSSLCert->SSLSubAltName->san_array[stSSLCert->SSLSubAltName->count].san),
								 "%s",
								 san);						
						stSSLCert->SSLSubAltName->count++;
					}	
				}			
			}
		}
		if(subjectAltNames)
		{
			GENERAL_NAMES_free(subjectAltNames);
		}
	}	

cert_return:
	if (x509_handle != NULL) 
	{
		X509_free(x509_handle);
	}
	return SSL_RETURN_NORM;
}

#define SSL_CERTIFICATE_HDRLEN  3
/*return : chain 个数*/
int ssl_read_all_cert(const char* conj_cert_buf, uint32_t conj_buflen, cert_chain_t* cert_unit, uint32_t unit_size)
{
	if(NULL==conj_cert_buf || 0==conj_buflen) return 0;
	char* 		unproc_cert = (char*)conj_cert_buf;	
	uint32_t	unproc_certlen = conj_buflen;		
	char*		cur_cert = NULL;
	uint32_t	cur_certlen = 0;
	uint32_t	cert_unit_cnt = 0;
	st_cert_t	stSSLCert[32];
	
    while ((int)unproc_certlen > 0)
    {
		if(cert_unit_cnt>=unit_size)
		{
			break;
		}
		cur_certlen = BtoL3BytesNum(unproc_cert);
		if((int)cur_certlen <0 || cur_certlen+SSL_CERTIFICATE_HDRLEN>unproc_certlen) 
		{
			break;
		}
		cur_cert = unproc_cert+SSL_CERTIFICATE_HDRLEN;		
		if(cert_unit_cnt<unit_size)
		{
			cert_unit[cert_unit_cnt].cert = cur_cert;
			cert_unit[cert_unit_cnt].cert_len = cur_certlen;			
			fn_pGetSSLInfo(cur_cert, cur_certlen, &stSSLCert[cert_unit_cnt]);				
		}		
		cert_unit_cnt++;
        unproc_certlen -= (SSL_CERTIFICATE_HDRLEN+cur_certlen);
		unproc_cert += SSL_CERTIFICATE_HDRLEN+cur_certlen;
	}
	return cert_unit_cnt;	
}

int main (int argc, char *argv[])
{
	char	cert_buf[5000] = {0};
	int 	cert_buflen = 0;
	FILE	*fp = NULL;
	cert_chain_t cert_unit[16];
	uint32_t unit_size = 16;
	int cert_cnt = 16;
	
	printf("%s %s\n", argv[0], argv[1]);
	if(((fp = fopen("./ssl_cert.crt", "rb"))!=NULL))
	{
		cert_buflen = fread(cert_buf, sizeof (char), 5000, fp);
		printf("%s\n", cert_buf);
		printf("the filesize of cert.crt is : %d\n", cert_buflen);
		cert_cnt = ssl_read_all_cert(cert_buf, cert_buflen, cert_unit, unit_size);		
		printf("the number of certuficate in cert.crt is : %d\n", cert_cnt);
		fclose(fp);
	}
	
    return 0;
}

