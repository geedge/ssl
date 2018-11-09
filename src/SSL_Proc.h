/*
 * SSL_Proc.h
 *
 *  Created on: 2013-5-3
 *      Author: lis
 */

#ifndef SSL_PROC_H_
#define SSL_PROC_H_

#include "ssl.h"

#ifdef __cplusplus
extern "C" {
#endif

int    BtoL1BytesNum(char *pcData);
int 	BtoL2BytesNum(char *pcData);
int 	BtoL3BytesNum(char *pcData);
int 	BtoL4BytesNum(char *pcData);

int 			ssl_protoRecg(char *pcData, int iDataLen);
UCHAR 			ssl_doWithVersion(ssl_stream **a_ssl_stream, struct streaminfo *a_tcp,
						unsigned long long region_flag, int thread_seq, void *a_packet);
UCHAR 			ssl_doWithApplicationData(ssl_stream **a_ssl_stream, struct streaminfo *a_tcp,
						unsigned long long region_flag, int thread_seq, void *a_packet);
UCHAR 			ssl_doWithCertificate(ssl_stream **a_ssl_stream, struct streaminfo *a_tcp,
						unsigned long long region_flag, int thread_seq, void *a_packet);
UCHAR 			ssl_doWithCertificateDetail(ssl_stream **a_ssl_stream, struct streaminfo *a_tcp,
						unsigned long long region_flag, int thread_seq, void *a_packet);
UCHAR 			ssl_doWithServerName(ssl_stream **a_ssl_stream, struct streaminfo *a_tcp,
						unsigned long long region_flag, int thread_seq, void *a_packet);
UCHAR 			ssl_doWithClientHello(ssl_stream **a_ssl_stream, struct streaminfo *a_tcp,
						unsigned long long region_flag, int thread_seq, void *a_packet);
UCHAR 			ssl_doWithServerHello(ssl_stream **a_ssl_stream, struct streaminfo *a_tcp,
						unsigned long long region_flag, int thread_seq, void *a_packet);
UCHAR 			ssl_callPlugins(ssl_stream **a_ssl_stream, struct streaminfo *a_tcp,
		 	 	 	 	unsigned long long region_flag, int thread_seq, void *a_packet);
int 			ssl_getLinkState(ssl_stream *a_ssl_stream);
int 			fn_iSslDecodeTagLength(char *pcTlvData, int iDataLen, int *pLenBytes);
void 			fn_vMemCpy(char *pcDst, int iMaxDstLen, char *pcSrc, int iSrcLen);
void 			fn_vPrintNum(char *pcDstBuff, unsigned char ucNum);

#ifdef __cplusplus
}
#endif

#endif /* SSL_PROC_H_ */
