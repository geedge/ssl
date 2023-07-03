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
#include <assert.h>

#include <openssl/x509.h>
#include <openssl/objects.h>
#include <openssl/safestack.h>
#include <openssl/cms.h>
#include <openssl/ocsp.h>
#include <openssl/ts.h>
#include <openssl/x509v3.h>

#include "SSL_Analyze.h"
#include "ssl.h"
#include "SSL_Message.h"
#include "SSL_Certificate.h"
#include "SSL_Proc.h"

#define CERT_VER_MAXNUM			3

const struct ssl_value2string g_certificate_version[] =
{
    {   0, "v1" },
    {   1, "v2" },
    {   2, "v3" },    
    {   3, "v4" },
    {   0, NULL },
};

const struct ssl_serial_string g_astAlgrithomTypes[] =
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

const struct ssl_serial_string g_astUserItemId[] =
{
    {{0X55, 0X04, 0X03}, "commonName"},
    {{0X55, 0X04, 0x0a}, "organizationName"},
    {{0X55, 0X04, 0x0b}, "organizationalUnitName"},
    {{0X55, 0X04, 0x07}, "localityName"},
    {{0X55, 0X04, 0x06}, "countryName"},    
    {{0X55, 0X1d, 0x11}, "altName"},
    {{0}, NULL},
};

/*return :  1 ���ڣ�0 ������*/
int ssl_read_specific_cert(const char* conj_cert_buf, uint32_t conj_buflen, uint8_t cert_type, char** cert, uint32_t* cert_len)
{
	if(NULL==conj_cert_buf || 0==conj_buflen) return 0;	
	if(CERT_TYPE_INDIVIDUAL!=cert_type && CERT_TYPE_ROOT!=cert_type && CERT_TYPE_MIDDLE!=cert_type && CERT_TYPE_CHAIN!=cert_type) return 0;
	char* 			unproc_cert = (char*)conj_cert_buf;	
	uint32_t		unproc_certlen = conj_buflen;		
	char*			cur_cert = NULL;
	uint32_t		cert_unit_cnt = 0;
	struct ssl_certificate_chain 	cert_unit[CERT_TYPE_MAXNUM];
	
    while (unproc_certlen > 0)
    {		
    	if(cert_unit_cnt>=CERT_TYPE_MAXNUM)
		{
			break;
		}
		cert_unit[cert_unit_cnt].cert_len = BtoL3BytesNum(unproc_cert);
		if(((int)cert_unit[cert_unit_cnt].cert_len <0) || cert_unit[cert_unit_cnt].cert_len+SSL_CERTIFICATE_HDRLEN>unproc_certlen) 
		{
			break;
		}
		cur_cert = unproc_cert+SSL_CERTIFICATE_HDRLEN;	
		if(cert_unit_cnt==0&&CERT_TYPE_INDIVIDUAL==cert_type)
		{
			*cert = cur_cert;
			*cert_len = cert_unit[cert_unit_cnt].cert_len;
			return 1;
		}
		cert_unit[cert_unit_cnt].cert = cur_cert;
        unproc_certlen -= (SSL_CERTIFICATE_HDRLEN+cert_unit[cert_unit_cnt].cert_len);
		unproc_cert += SSL_CERTIFICATE_HDRLEN+cert_unit[cert_unit_cnt].cert_len;
		cert_unit_cnt++;

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

/*return : chain ����*/
int ssl_read_all_cert(const char* conj_cert_buf, uint32_t conj_buflen, struct ssl_certificate_chain* cert_unit, uint32_t unit_size)
{
	if(NULL==conj_cert_buf || 0==conj_buflen) return 0;
	char* 		unproc_cert = (char*)conj_cert_buf;	
	uint32_t	unproc_certlen = conj_buflen;		
	char*		cur_cert = NULL;
	uint32_t	cert_unit_cnt = 0;
	
	while ((int)unproc_certlen > 0)
	{
		if(cert_unit_cnt>=unit_size)
		{
			break;
		}
		
		cert_unit[cert_unit_cnt].cert_len = BtoL3BytesNum(unproc_cert);
		if((int)cert_unit[cert_unit_cnt].cert_len <0 || cert_unit[cert_unit_cnt].cert_len+SSL_CERTIFICATE_HDRLEN>unproc_certlen) 
		{
			break;
		}
		
		cur_cert = unproc_cert+SSL_CERTIFICATE_HDRLEN;	
		cert_unit[cert_unit_cnt].cert=cur_cert;
		unproc_certlen -= (SSL_CERTIFICATE_HDRLEN+cert_unit[cert_unit_cnt].cert_len);
		unproc_cert += SSL_CERTIFICATE_HDRLEN+cert_unit[cert_unit_cnt].cert_len;
		cert_unit_cnt++;
	}
	
	return cert_unit_cnt;
}

int x509_parse_certificate_detail(struct ssl_certificate *certificate, char *cert_payload, int cert_payload_len, int thread_seq)
{
    int state=SSL_TRUE;
    int san_count=0;
	X509_NAME *issuer = NULL;
    X509_NAME *subject = NULL;

    ASN1_STRING *serial = NULL;
	ASN1_STRING *san_name = NULL;
    
	GENERAL_NAME *generalName = NULL;
    GENERAL_NAMES *subjectAltNames = NULL;
    
    ASN1_TIME *start = NULL;
    ASN1_TIME *end = NULL;
	
	EVP_PKEY *pkey = NULL;
	const ASN1_OBJECT *salg;
    const X509_ALGOR *tsig_alg;
	
	X509 *x509_handle = d2i_X509(NULL, (unsigned char const **)&cert_payload, cert_payload_len);
	if (x509_handle == NULL) 
	{
		return SSL_FLASE;
	}
	
    /*version*/
    int ver = X509_get_version(x509_handle);
    if(ver>CERT_VER_MAXNUM || ver<0) 
    {
        state=SSL_FLASE;
        goto cert_return;
    }

    certificate->version.len=(unsigned char)strlen((const char *)g_certificate_version[ver].string);
    certificate->version.value=(unsigned char *)g_certificate_version[ver].string;

    /*serial num*/
    serial = X509_get_serialNumber(x509_handle);
    if (NULL != serial)
    {
        certificate->serial.len=MIN(ASN1_STRING_length(serial), (int)(sizeof(certificate->serial.value)-1));
        memcpy(certificate->serial.value, ASN1_STRING_get0_data(serial), certificate->serial.len);
    }

    /*SSL AgID*/
    tsig_alg = X509_get0_tbs_sigalg(x509_handle);
    X509_ALGOR_get0(&salg, NULL, NULL, tsig_alg);
    OBJ_obj2txt((char*)certificate->signature_algorithm.value, sizeof(certificate->signature_algorithm.value), salg, 1);
    certificate->signature_algorithm.len=strlen((const char *)certificate->signature_algorithm.value);

    /*SSL Issuer*/
    issuer = X509_get_issuer_name(x509_handle);
    if(NULL!=issuer)
    {
        X509_NAME_get_text_by_NID(issuer, NID_commonName, certificate->issuer.common, sizeof(certificate->issuer.common));
        X509_NAME_get_text_by_NID(issuer, NID_organizationName, certificate->issuer.organization, sizeof(certificate->issuer.organization));
        X509_NAME_get_text_by_NID(issuer, NID_organizationalUnitName, certificate->issuer.organizational_unit, sizeof(certificate->issuer.organizational_unit));
        X509_NAME_get_text_by_NID(issuer, NID_localityName, certificate->issuer.locality, sizeof(certificate->issuer.locality));
        X509_NAME_get_text_by_NID(issuer, NID_streetAddress, certificate->issuer.street_address, sizeof(certificate->issuer.street_address));
        X509_NAME_get_text_by_NID(issuer, NID_stateOrProvinceName, certificate->issuer.state_or_Province, sizeof(certificate->issuer.state_or_Province));			
        X509_NAME_get_text_by_NID(issuer, NID_countryName,  certificate->issuer.country, sizeof(certificate->issuer.country));

        snprintf(certificate->issuer.rdn_sequence_list,
                    sizeof(certificate->issuer.rdn_sequence_list),
                    "%s;%s;%s;%s;%s;%s;%s",
                    certificate->issuer.common,
                    certificate->issuer.organization,
                    certificate->issuer.organizational_unit,
                    certificate->issuer.locality,
                    certificate->issuer.street_address,
                    certificate->issuer.state_or_Province,
                    certificate->issuer.country);
    }

    /*SSL Subject*/
    subject = X509_get_subject_name(x509_handle);
    if(NULL!=subject)
    {
        X509_NAME_get_text_by_NID(subject, NID_commonName, certificate->subject.common, sizeof(certificate->subject.common));
        X509_NAME_get_text_by_NID(subject, NID_organizationName, certificate->subject.organization, sizeof(certificate->subject.organization));
        X509_NAME_get_text_by_NID(subject, NID_countryName, certificate->subject.country, sizeof(certificate->subject.country));
        X509_NAME_get_text_by_NID(subject, NID_organizationalUnitName, certificate->subject.organizational_unit, sizeof(certificate->subject.organizational_unit));
        X509_NAME_get_text_by_NID(subject, NID_localityName, certificate->subject.locality, sizeof(certificate->subject.locality));
        X509_NAME_get_text_by_NID(subject, NID_streetAddress, certificate->subject.street_address, sizeof(certificate->subject.street_address));
        X509_NAME_get_text_by_NID(subject, NID_stateOrProvinceName, certificate->subject.state_or_Province, sizeof(certificate->subject.state_or_Province));			
        
        snprintf(certificate->subject.rdn_sequence_list,
                    sizeof(certificate->subject.rdn_sequence_list),
                    "%s;%s;%s;%s;%s;%s;%s",
                    certificate->subject.common,
                    certificate->subject.organization,
                    certificate->subject.organizational_unit,
                    certificate->subject.locality,
                    certificate->subject.street_address,
                    certificate->subject.state_or_Province,
                    certificate->subject.country);
    }

    /*SSL Subject keyInfo*/
    pkey = X509_get_pubkey(x509_handle);
    if(pkey!=NULL)
    {
    	//https://www.openssl.org/docs/man3.0/man3/i2d_PublicKey.html
        certificate->subject_key.len=i2d_PublicKey(pkey, NULL);
		if(certificate->subject_key.len>0)
		{
	        certificate->subject_key.value=(char *)dictator_malloc(thread_seq, certificate->subject_key.len);		
	        int ret=i2d_PublicKey(pkey, (unsigned char **)&(certificate->subject_key.value)); //!!! point will be changed
	        if(ret>0)
	        {
	        	 certificate->subject_key.value=certificate->subject_key.value-certificate->subject_key.len;
	        }
			else
			{
				dictator_free(thread_seq, (void *)certificate->subject_key.value);
				certificate->subject_key.value=NULL;
				 certificate->subject_key.len=0;
			}
		}
        EVP_PKEY_free(pkey);
    }		
            
    /*validity*/
    start = X509_get_notBefore(x509_handle);
    end = X509_get_notAfter(x509_handle);
    sprintf(certificate->validity.before, "%s", start->data);
    sprintf(certificate->validity.after, "%s", end->data);				

    /*subject bak*/	
    subjectAltNames=(GENERAL_NAMES*)X509_get_ext_d2i(x509_handle, NID_subject_alt_name, NULL, NULL);  
    if(!subjectAltNames)
    {
        goto cert_return;
    }

    san_count=sk_GENERAL_NAME_num(subjectAltNames);
    if(san_count>0)
    {
        certificate->subject_alter.num=0;
        certificate->subject_alter.name=(char (*)[MAX_ALTER_NAME_LEN])dictator_malloc(thread_seq, san_count * sizeof(char[MAX_ALTER_NAME_LEN]));
        
        for (int i=0; i<san_count; i++)
        {       
            generalName = sk_GENERAL_NAME_value(subjectAltNames, i);
            if(!generalName)
            {
                break;
            }

            if(GEN_DNS == generalName->type)
            {
                san_name = (ASN1_STRING*)GENERAL_NAME_get0_value(generalName, NULL);
                if(ASN1_STRING_length(san_name)>0)
                {
                    char *san=(char*)ASN1_STRING_get0_data(san_name);
                    int length=MIN(strlen(san), sizeof(certificate->subject_alter.name[certificate->subject_alter.num])-1);
                    memcpy(certificate->subject_alter.name[certificate->subject_alter.num], san, length);
					certificate->subject_alter.name[certificate->subject_alter.num][length]='\0';
                    certificate->subject_alter.num++;
                }	
            }			
        }
    }

    if(subjectAltNames)
    {
        GENERAL_NAMES_free(subjectAltNames);
    }

    //https://www.openssl.org/docs/man1.1.1/man3/X509_ALGOR_get0.html
    X509_ALGOR_get0(&salg, NULL, NULL, X509_get0_tbs_sigalg(x509_handle));
    OBJ_obj2txt(certificate->algorithm_identifier.value, sizeof(certificate->algorithm_identifier.value), salg, 1);
    certificate->algorithm_identifier.len=strlen((const char *)certificate->algorithm_identifier.value);

cert_return:
	if (x509_handle != NULL) 
	{
		X509_free(x509_handle);
	}

	return state;
}
