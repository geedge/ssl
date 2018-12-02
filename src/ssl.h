
#ifndef H_SSL_H
#define H_SSL_H

#include <stdio.h>
#include <string.h>

#define SSH_H_VERSION_20160910_ADD_CERT				0

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
	unsigned short  		suite_len;	//4 
	unsigned char*			suite_value;	
}st_suites_t;

typedef struct _st_compress_methods_t
{
	unsigned char 			methlen;	
	unsigned char*			methods;//default 0:null
}st_compress_methods_t;

//#############################################client hello
#define CLIENT_HELLO_HDRLEN 		4
#define MAX_EXTENSION_NUM			16
#define MAX_EXT_DATA_LEN			256
#define SERVER_NAME_EXT_TYPE		0x0000
#define SERVER_NAME_HOST_TYPE 	0x0000
#define SERVER_NAME_OTHER_TYPE 	0x0008


typedef struct _st_client_ext_t
{
	unsigned short 			type;
	unsigned short 			len;
	unsigned char 			data[MAX_EXT_DATA_LEN];//if longer,cut off
}__attribute__((packed))st_client_ext_t;

typedef struct _st_client_server_name_t
{
	short 					server_name_list_len;
	unsigned short 			server_name_type;
	unsigned char 			server_name_len;
	unsigned char* 			server_name_data;
}__attribute__((packed))st_client_server_name_t;


//client hello info
typedef struct _st_client_hello_t
{
	int 						totallen;	//3 
	unsigned short 				client_ver;	
	st_random_t 				random;	//32 byte random,not used currently
	st_session_t 				session;	
	st_suites_t 				ciphersuits;
	st_compress_methods_t 		com_method;	//compress method
	unsigned short 				extlen;	
	unsigned short 				ext_num;	//number of extensions
	st_client_ext_t 			exts[MAX_EXTENSION_NUM];	//extensions content:1 or more extentions
	unsigned char 				server_name[512];  	// server_name = host_name+...
}st_client_hello_t;

//#############################################client hello end

//#############################################server hello
#define  SERVER_HELLO_HDRLEN 4

//client hello info
typedef struct _st_server_hello_t
{
	int 					totallen;	//3 
	unsigned short 			client_ver;	
	st_random_t 			random;	//32 byte random,not used currently
	st_session_t 			session;	
	st_suites_t 			ciphersuits;
	st_compress_methods_t 	com_method;	//compress method
}st_server_hello_t;

//#############################################server hello end

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
	unsigned int 				uiSslVersion;

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
}ssl_stream;

/*ssl_read_all_cert中的结构体*/
typedef struct cert_chain_s
{
     char* 						cert;
	 uint32_t					cert_len;
}cert_chain_t;

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

const char* ssl_get_suite(st_suites_t* ciphersuits);


#ifdef __cplusplus
}
#endif

#endif



