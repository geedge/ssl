
#ifndef H_SSL_MESSAGE_H
#define H_SSL_MESSAGE_H

#include <stdio.h>
#include <string.h>

#define MIN(a, b)                    ((a) <= (b) ? (a):(b))

#define MAX_DATA_BUFFER  			40960


#define SSL_HEADER_LEN	5+1	//use the hand_shake first bytes

#define SSL_KEY 					3
#define SSL_TRUE 					1
#define SSL_FLASE 					0


#define RANDOM_TIME_LEN 			4
#define SSL_RANDOM_SIZE 			28

/**SSL versions**/
#define UNKNOWN_VERSION        		0x0000
#define SSLV3_VERSION          		0x0300
#define SSLV2_VERSION          		0x0002
#define TLSV1_VERSION          		0x0301
#define TLSV1_2_VERSION          	0x0303
#define TLSV1DOT1_VERSION      		0x0302
#define DTLSV1DOT0_VERSION     		0xfeff
#define DTLSV1DOT0_VERSION_NOT 		0x0100

#define SSL_HANDSHAKE_MSG_HDRLEN    4
#define SSL_RECORD_HDRLEN  			5
#define SSL_HELLO_PROTO_HDRLEN  	6

#define SSL_HANDSHAKE_NOTRUNK       0
#define SSL_HANDSHAKE_PROTO_TRUNKED 1
#define SSL_HANDSHAKE_MSG_TRUNKED   2

#define CHANGE_CIPHER_SEP 			0x14
#define ALERT			 			0x15
#define HANDSHAKE 					0x16
#define APPLICATION_DATA 			0x17

#define CERT_MAXNUM			 		8

typedef struct _stValueString_t
{
    unsigned int 			uiValue;
    const char 				*pcString;
}stValueString_t;

typedef struct _stSerialString_t
{
    unsigned char 			aucSerial[16];
    const char 				*pcString;
}stSerialString_t;

typedef struct _stSSLRecordHdr_t
{
    unsigned char 			ucContType;
    unsigned short 			usVersion;
    unsigned short 			usTotalLen;

}__attribute__((packed))stSSLRecordHdr_t;


typedef struct _stHandShakeTypeHdr_t
{
    unsigned char 			ucContType;
}__attribute__((packed))stHandShakeTypeHdr_t;

typedef struct _stHSkCertificateHdr_t
{
    //unsigned char pacCertLen[3];
}stHSkCertificateHdr_t;

typedef enum _emHelloMsgType_m
{
//    HELLO_REQUEST = 0,
    CLIENT_HELLO = 1,
    SERVER_HELLO = 2,
    CERTIFICATE = 11,
 //   SERVER_KEY_EXCHANGE = 12,
//    CERTIFICATE_REQUEST = 13,
//    SERVER_HELLO_DONE = 14,
//    CERTIFICATE_VERIFY = 15,
//    CLIENT_KEY_EXCHANGE = 16,
//   FINISHED = 20,
    MSG_UNKNOWN = 255,
}emHelloMsgType_m;

UCHAR ssl_analyseStream(struct streaminfo *a_tcp, void** pme, int thread_seq, void *a_packet);

#endif

