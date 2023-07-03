#pragma once

#define MIN(a, b)                    ((a) <= (b) ? (a):(b))


#define SSL_HEADER_LEN	5+1	//use the hand_shake first bytes

#define SSL_KEY 		3
#define SSL_CONTINUE	2
#define SSL_TRUE 		1
#define SSL_FLASE 		0


#define RANDOM_TIME_LEN 			4
#define SSL_RANDOM_SIZE 			28


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


//#############################################client hello
#define CLIENT_HELLO_HDRLEN 		4

struct client_server_name
{
	short 					list_len;
	unsigned short 			type;
	unsigned char 			len;
	unsigned char* 			data;
}__attribute__((packed));

#define  SERVER_HELLO_HDRLEN 		4

#define CERTIFICATE_HDRLEN			7
#define SSL_CERTIFICATE_HDRLEN  	3

struct ssl_value2string
{
    unsigned int value;
    const char *string;
};

struct ssl_serial_string
{
    unsigned char serial[16];
    const char *string;
};

struct ssl_record_header
{
    unsigned char content_type;
    unsigned short version;
    unsigned short total_len;
}__attribute__((packed));


struct ssl_handshake_type
{
    unsigned char content_type;
}__attribute__((packed));

enum SSL_HANDSHAKE_TYPE
{
    CLIENT_HELLO=1,
    SERVER_HELLO=2,
    CERTIFICATE=11,
	NEW_SESSION_TICKET=4,
    MSG_UNKNOWN=255,
};

int ssl_parse_stream(const struct streaminfo *a_tcp, struct ssl_runtime_context *ssl_context, int thread_seq, const void *a_packet);

