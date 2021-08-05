
#ifndef H_SSL_H
#define H_SSL_H

#include <stdio.h>
#include <string.h>

#define SSH_H_VERSION_20210805_ssl20		0

#define SSL_KEY 									3
#define SSL_TRUE 								1
#define SSL_FLASE 								0


#define SSL_INTEREST_KEY		(1<<SSL_INTEREST_KEY_MASK)
#define SSL_CERTIFICATE			(1<<SSL_CERTIFICATE_MASK)
#define SSL_CERTIFICATE_DETAIL	(1<<SSL_CERTIFICATE_DETAIL_MASK)
#define SSL_APPLICATION_DATA	(1<<SSL_APPLICATION_DATA_MASK)
#define SSL_CLIENT_HELLO		(1<<SSL_CLIENT_HELLO_MASK)
#define SSL_SERVER_HELLO		(1<<SSL_SERVER_HELLO_MASK)
#define SSL_VERSION				(1<<SSL_VERSION_MASK)
#define SSL_ALERT				(1<<SSL_ALERT_MASK)
#define SSL_NEW_SESSION_TICKET	(1<<SSL_NEW_SESSION_TICKET_MASK)

/**SSL versions, variate uiSslVersion in ssl_stream**/
#define UNKNOWN_VERSION        		0x0000
#define SSLV3_VERSION          		0x0300
#define SSLV2_VERSION          		0x0002
#define TLSV1_0_VERSION          	0x0301
#define TLSV1_1_VERSION      		0x0302
#define TLSV1_2_VERSION          	0x0303
#define DTLSV1_0_VERSION     		0xfeff
#define DTLSV1_0_VERSION_NOT 		0x0100

typedef enum
{
	/*1*/
	SSL_INTEREST_KEY_MASK = 0,
	SSL_CERTIFICATE_DETAIL_MASK = 1,
	SSL_CLIENT_HELLO_MASK = 2,	
	SSL_SERVER_HELLO_MASK= 3,	
	SSL_CERTIFICATE_MASK,	
	SSL_APPLICATION_DATA_MASK,
	SSL_VERSION_MASK,
	SSL_ALERT_MASK,
	SSL_NEW_SESSION_TICKET_MASK,
}ssl_interested_region;

typedef struct cdata_buf
{
	char*					p_data;
	unsigned int 			data_size;		
}cdata_buf;

typedef struct _st_random_t
{
	unsigned int 			gmt_time;	//4 
	unsigned char 			random_bytes[28];	//28 byte random_bytes
}st_random_t;

typedef struct _st_session_t
{
	unsigned char 			session_len;	//4 
	unsigned char*			session_value;	
}st_session_t;

typedef struct _st_suites_t
{
	unsigned short  		suites_len;	    //4 
	unsigned char*			suites_value;	//ciphersuites list, split into 2 bytes and get suite name by "ssl_get_suite"
}st_suites_t;

typedef struct _st_compress_methods_t
{
	unsigned char 			methlen;	
	unsigned char*			methods;        //default 0:null
}st_compress_methods_t;

typedef struct _st_session_tciket_t
{
	unsigned char 			ticketlen;	
	unsigned char*			ticket;         //default 0:null
}st_session_tciket_t;

#define SUITE_VALUELEN					2
#define KEY_EXCHANGELEN_LEN				4
#define RECORD_DIGESTLEN_LEN			2
#define ESNILEN_LEN						2
typedef struct _st_esni_t
{		
	unsigned short 			key_exchange_group;
	unsigned short 			key_exchange_len;
	unsigned char* 			key_exchange;
	unsigned char* 			record_digest;
	unsigned short 			record_digest_len;
	unsigned short 			esni_len;
	unsigned char* 			esni;	
	unsigned char* 			suite_value; //get suite name by "ssl_get_suite"function
}st_esni_t;

//#############################################client hello
#define MAX_EXTENSION_NUM					16
#define MAX_EXT_DATA_LEN					256
#define SERVER_NAME_EXT_TYPE				0x0000
#define SERVER_NAME_HOST_TYPE 				0x0000
#define SERVER_NAME_OTHER_TYPE 				0x0008
#define SESSION_TICKET_EXT_TYPE 			0x0023
#define ENCRPTED_SERVER_NAME_EXT_TYPE		0xFFCE


/*important extension in clientHello: alpn(application_layer_protocol_negotiation) */
#define ALPN_EXT_TYPE				0x0010


typedef struct _st_ext_t
{
	unsigned short 			type;
	unsigned short 			len;
	unsigned char* 			data;
}st_ext_t;


//client hello info
typedef struct _st_client_hello_t
{
	int 						totallen;	//3 
	unsigned short 				client_ver;	
	st_random_t 				random;	//32 byte random,not used currently
	st_session_t 				session;	
	st_suites_t 				ciphersuites;
	st_compress_methods_t 		com_method;	//compress method
	unsigned short 				extlen;	
	unsigned short 				ext_num;	//number of extensions
	st_ext_t 					exts[MAX_EXTENSION_NUM];	//extensions content:1 or more extentions
	unsigned char 				server_name[512];  	// server_name = host_name+...
	st_session_tciket_t 		session_ticket;	
	st_esni_t 					encrypted_server_name;	
}st_client_hello_t;

//#############################################client hello end

//#############################################server hello
#define  SERVER_HELLO_HDRLEN 4

//client hello info
typedef struct _st_server_hello_t
{
	int 					totallen;	//3 
	unsigned short 			server_ver;	
	st_random_t 			random;	//32 byte random,not used currently
	st_session_t 			session;	
	st_suites_t 			ciphersuites;
	st_compress_methods_t 	com_method;	//compress method
	unsigned short 			extlen;						//the length of all extensions
	unsigned short 			ext_num;					//the number of extensions
	st_ext_t 				exts[MAX_EXTENSION_NUM];	//the content of extensions :1 or more extentions
	
}st_server_hello_t;

//#############################################server hello end


//#############################################new session ticket
#define  SESSION_TICKET_HDRLEN 4

//client hello info
typedef struct _st_new_session_ticket_t
{
	int 					totallen;	//3 bytes
	int 					lifttime;	//second
	int 					ticket_len;	//3 bytes
	unsigned char* 			ticket;	
}st_new_session_ticket_t;

//#############################################new session ticket end


//#############################################certificate
#define CERTIFICATE_HDRLEN		7
#define SSL_CERTIFICATE_HDRLEN  3
//#define SAN_MAXNUM  			128

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
	char 					SSLIssuer[512];  //commonName +  organizationName + organizationalUnitName + localityName + streetAddress + stateOrProvinceName + countryName	
	char 					SSLSub[512]; //commonName +  organizationName + organizationalUnitName + localityName + streetAddress + stateOrProvinceName + countryName
	char 					SSLFrom[80];     
	char 					SSLTo[80];     
	char 					SSLFPAg[32];  	 	
	char 					SSLIssuerC[64]; //countryName  	
	char 					SSLIssuerO[64]; //organizationName
	char 					SSLIssuerCN[64];//commonName	
	char 					SSLSubC[64]; //countryName  	
	char 					SSLSubO[64]; //organizationName
	char 					SSLSubCN[64];//commonName		
	st_san_t* 				SSLSubAltName;  
	uint8_t 				cert_type;
	unsigned char*			SSLSubKey;
	int						SSLSubKeyLen;	
	uint8_t 				SSLSerialNumLen;
	
	char 					SSLIssuerP[64];//stateOrProvinceName
	char 					SSLIssuerS[64];//streetAddress
	char 					SSLIssuerL[64];//localityName
	char 					SSLIssuerU[64];//organizationalUnitName

	char 					SSLSubP[64];//stateOrProvinceName
	char 					SSLSubS[64];//streetAddress
	char 					SSLSubL[64];//localityName
	char 					SSLSubU[64];//organizationalUnitName
	
}st_cert_t;

//#############################################certificate end


typedef struct _business_infor_t
{
	void*						param;
	unsigned char				return_value;
}business_infor_t;

typedef struct _ssl_stream_t
{
	unsigned long long 			output_region_flag;
	unsigned char 				link_state;
	unsigned char 				over_flag;
	unsigned char 				ucContType;
	unsigned char 				is_ssl_stream;	
	unsigned short 				uiSslVersion; //SSL versions, definition like TLSV1_2_VERSION in ssl.h

	int 						uiAllMsgLen; //hand shake msg length  
	int 						uiMsgProcLen;
	unsigned int 				uiMsgState;   	
	int 						uiMaxBuffLen;

	
	cdata_buf*					p_output_buffer;
	st_client_hello_t*			stClientHello;	
	st_server_hello_t*			stServerHello;
	st_cert_t*					stSSLCert;	

	business_infor_t*			business;

	char*						pcSslBuffer;	 
	ssl_interested_region 		output_region_mask;	
	int 						uiCurBuffLen; 
	
	st_new_session_ticket_t*		stNewSessionTicket;
	unsigned char 				first_pkt_flag;	
}ssl_stream;

/*ssl_read_all_cert中的结构体*/
typedef struct cert_chain_s
{
     char* 						cert;
	 uint32_t					cert_len;
}cert_chain_t;

/*ssl_get_alpn_list?Dμ??á11ì?*/
typedef struct alpn_list_s
{
	 char*						alpn;			//pointer to exts
	 uint32_t					alpn_len;
}alpn_list_t;

/*ssl_read_specific_cert中cert_type的参数*/
#define CERT_TYPE_INDIVIDUAL		0  //个人证书
#define CERT_TYPE_ROOT				1  //根证书
#define CERT_TYPE_MIDDLE			2  //中间证书，个人证书的上级证书
#define CERT_TYPE_CHAIN				3  //其他: 格式[len(3bytes)+cert+len(3bytes)+certlen(3bytes)+cert......]

#ifdef __cplusplus
extern "C" {
#endif

/*return : chain 个数, 按照从个人证书到根证书的顺序存储*/
int ssl_read_all_cert(const char* conj_cert_buf, uint32_t conj_buflen, cert_chain_t* cert_unit, uint32_t unit_size);

/*return :  1 存在，0 不存在*/
int ssl_read_specific_cert(const char* conj_cert_buf, uint32_t conj_buflen, uint8_t cert_type, char** cert, uint32_t* cert_len);

/*Obtain suite name like "TLS_RSA_WITH_AES_128_CBC_SHA" by suite_value; Each suite should be 2 bytes*/
const char* ssl_get_suite_name(unsigned char* suite_value, unsigned short suite_len);

/*Obtain version name like "TLS1.2" by version*/
const char* ssl_get_version_name(unsigned short version);

/*Obtain alpl list by */
/*
input: stClientHello; alpn_list is applied by user 
output: put the results in alpn_list
return: the number of alpn
*/
int ssl_get_alpn_list(alpn_list_t* alpn_list, int alpn_size, st_ext_t* exts, unsigned short ext_num);

const char* ssl_get_suite(st_suites_t* ciphersuits);

struct _ssl_ja3_info_t
{
	int sni_len;
	int fp_len;
	char *sni;
	char *fp;
};

int ssl_ja3_init(void);
struct _ssl_ja3_info_t *ssl_get_ja3_fingerprint(struct streaminfo *stream, unsigned char *payload, int payload_len, int thread_seq);

#ifdef __cplusplus
}
#endif

#endif



