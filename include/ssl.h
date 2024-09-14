#pragma once

enum ssl_interested_region
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
};

#define SSL_INTEREST_KEY		(1<<SSL_INTEREST_KEY_MASK)
#define SSL_CERTIFICATE			(1<<SSL_CERTIFICATE_MASK)
#define SSL_CERTIFICATE_DETAIL	(1<<SSL_CERTIFICATE_DETAIL_MASK)
#define SSL_APPLICATION_DATA	(1<<SSL_APPLICATION_DATA_MASK)
#define SSL_CLIENT_HELLO		(1<<SSL_CLIENT_HELLO_MASK)
#define SSL_SERVER_HELLO		(1<<SSL_SERVER_HELLO_MASK)
#define SSL_VERSION				(1<<SSL_VERSION_MASK)
#define SSL_ALERT				(1<<SSL_ALERT_MASK)
#define SSL_NEW_SESSION_TICKET	(1<<SSL_NEW_SESSION_TICKET_MASK)

#define UNKNOWN_VERSION		0x0000
#define SSLV3_VERSION		0x0300
#define SSLV2_VERSION		0x0002
#define TLSV1_0_VERSION		0x0301
#define TLSV1_1_VERSION		0x0302
#define TLSV1_2_VERSION		0x0303
#define TLSV1_3_VERSION		0x0304
#define DTLSV1_0_VERSION	0xfeff
#define DTLSV1_2_VERSION	0xfefd
#define DTLSV1_3_VERSION	0xfefc
#define DTLSV1_0_VERSION_NOT 0x0100
#define TLCPV1_VERSION		0x0101

struct cdata_buf
{
	char* p_data;
	unsigned int data_size;
};

struct ssl_l1v
{
	unsigned char len;
	unsigned char *value;
};

struct ssl_l2v
{
	unsigned short len;
	unsigned char *value;
};

struct ssl_l2tv
{
	unsigned short len;
	unsigned short type;
	unsigned char *value;
};

struct ssl_random
{
	unsigned int gmt_time;
	struct ssl_l1v bytes;
};

struct ssl_encrypt_server_name
{
	unsigned char is_esni;
	unsigned short key_exchange_group;
	struct ssl_l2v esni;
	struct ssl_l2v suite; //get suite name by "ssl_get_suite"function
	struct ssl_l2v key_exchange;
	struct ssl_l2v record_digest;
};

struct ssl_extenstions;

#define MAX_JA_MD5_STR_LEN		128
struct ssl_ja_fingerprint
{
	int value_sz;
	char value[MAX_JA_MD5_STR_LEN];
};

#define	MAX_SERVER_NAME_LEN	512
struct ssl_client_hello
{
	int total_len; //3
	unsigned short version;
	struct ssl_random random;
	struct ssl_l1v session;
	struct ssl_l2v ciphersuites;
	struct ssl_l1v compress_method;
	struct ssl_l2tv *encrypt_chello;
	struct ssl_l2tv *session_ticket;
	struct ssl_l2tv *alpn;
	struct ssl_extenstions *extensions;
	struct ssl_encrypt_server_name esni;
	char server_name[MAX_SERVER_NAME_LEN];
	struct ssl_ja_fingerprint ja3;
	struct ssl_ja_fingerprint ja4;
};

struct ssl_server_hello
{
	int total_len;	//3 
	unsigned short version;
	unsigned short extension_len;
	unsigned short extension_num;

	struct ssl_random random;
	struct ssl_l1v session;
	struct ssl_l2v ciphersuites;
	struct ssl_l1v compress_method;
	struct ssl_extenstions *extensions;
	struct ssl_ja_fingerprint ja3s;
	struct ssl_ja_fingerprint ja4s;
};

struct ssl_new_session_ticket
{
	int total_len;	//3 bytes
	int lift_time;	//second
	int ticket_len;	//3 bytes
	unsigned char* ticket;
};

#define MAX_ALTER_NAME_LEN		64
struct ssl_subject_alter_name
{
	int num;
	char (*name)[MAX_ALTER_NAME_LEN];
};

#define MAX_RDN_SEQUENCE_LEN		64
#define MAX_RDN_SEQUENCE_LIST_LEN	512
struct ssl_rdn_sequence
{
	char common[MAX_RDN_SEQUENCE_LEN];				//commonName
	char country[MAX_RDN_SEQUENCE_LEN];				//countryName
	char locality[MAX_RDN_SEQUENCE_LEN];				//localityName
	char postal_code[MAX_RDN_SEQUENCE_LEN];			// postalCode
	char organization[MAX_RDN_SEQUENCE_LEN];			//organizationName
	char street_address[MAX_RDN_SEQUENCE_LEN];		//streetAddress
	char state_or_Province[MAX_RDN_SEQUENCE_LEN];		//stateOrProvinceName
	char organizational_unit[MAX_RDN_SEQUENCE_LEN];	//organizationalUnitName
	char rdn_sequence_list[MAX_RDN_SEQUENCE_LIST_LEN];  //commonName +  organizationName + organizationalUnitName + localityName + streetAddress + stateOrProvinceName + countryName	
};

#define	MAX_VALIDITY_LEN	80
struct ssl_validity
{
	char before[MAX_VALIDITY_LEN];
	char after[MAX_VALIDITY_LEN];
};

struct ssl_subject_public_key
{
	int len;
	char*value;
};

#define MAX_SERIAL_NUMBER_LEN	128
struct ssl_serial_number
{
	unsigned char len;
	char value[MAX_SERIAL_NUMBER_LEN];
};

#define MAX_SIGNATURE_ALGORITHM_ID_LEN	64
struct ssl_signature_algorithm_id
{
	unsigned char len;
	char value[MAX_SIGNATURE_ALGORITHM_ID_LEN];
};

#define MAX_ALGORITHM_IDENTIFIER	64
struct ssl_algorithm_identifier
{
	unsigned char len;
	char value[MAX_ALGORITHM_IDENTIFIER];
};

struct ssl_certificate
{
	int total_len;
	int cert_len;
	char cert_type;
	
	struct ssl_l1v version;
	struct ssl_validity validity;
	struct ssl_serial_number serial;
	struct ssl_rdn_sequence issuer;
	struct ssl_rdn_sequence subject;
	
	struct ssl_subject_public_key subject_key;
	struct ssl_subject_alter_name subject_alter;
	struct ssl_algorithm_identifier algorithm_identifier;
	struct ssl_signature_algorithm_id signature_algorithm;
};

struct ssl_stream
{
	struct ssl_client_hello* chello;
	struct ssl_server_hello* shello;
	struct ssl_certificate *certificate;
	struct ssl_new_session_ticket *new_session_ticket;
};

struct ssl_certificate_chain
{
	char* cert;
	uint32_t cert_len;
};

struct ssl_alpn_list
{
	 char* alpn; //pointer to exts
	 uint32_t alpn_len;
};

#define CERT_TYPE_INDIVIDUAL		0
#define CERT_TYPE_ROOT				1
#define CERT_TYPE_MIDDLE			2
#define CERT_TYPE_CHAIN				3

const char* ssl_get_suite(struct ssl_l2v* ciphersuits);
const char* ssl_get_version_name(unsigned short version);
const char* ssl_get_suite_name(unsigned char* suite_value, unsigned short suite_len);
int ssl_get_alpn_list(struct ssl_l2tv *extension_alpn, struct ssl_alpn_list* alpn_list, int alpn_size);
int ssl_read_specific_cert(const char* conj_cert_buf, uint32_t conj_buflen, uint8_t cert_type, char** cert, uint32_t* cert_len);
int ssl_read_all_cert(const char* conj_cert_buf, uint32_t conj_buflen, struct ssl_certificate_chain* cert_unit, uint32_t unit_size);
