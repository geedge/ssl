/*
 * SSL_Certificate.h
 *
 *  Created on: 2013-5-8
 *      Author: lis
 */

#ifndef SSL_CERTIFICATE_H_
#define SSL_CERTIFICATE_H_


#define	CERT_TYPE_MAXNUM			16

#ifdef __cplusplus
extern "C" {
#endif

char *fn_pcGetElemType(unsigned char *pucId, int iIdLen, stSerialString_t *pastElemTypes);

UCHAR fn_pGetSSLInfo(char *pcCert, int iLen, ssl_stream *a_ssl_stream,  struct streaminfo *a_tcp,
		        unsigned long long region_flag, int thread_seq, void *a_packet);

UCHAR ssl_AnalyseCertificate(char *pcSslCertificateData, int iDataLen, ssl_stream *a_ssl_stream, struct streaminfo* a_tcp,
		                      unsigned long long region_flag, int thread_seq, void* a_packet);
UCHAR ssl_Certificate(char *pcSslCertificateData, int iDataLen, ssl_stream *a_ssl_stream, struct streaminfo* a_tcp,
		                      unsigned long long region_flag, int thread_seq, void* a_packet);


#ifdef __cplusplus
}
#endif

#endif /* SSL_CERTIFICATE_H_ */
