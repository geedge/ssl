#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "SSL_Analyze.h"
#include "ssl.h"
#include "SSL_Message.h"
#include "SSL_Proc.h"
#include "SSL_Certificate.h"


#define SUITE_VALUELEN					2
#define KEY_EXCHANGELEN_LEN				4
#define RECORD_DIGESTLEN_LEN			2
#define ESNILEN_LEN						2
#define SERVER_HELLO_HDRLEN 4
#define SESSION_TICKET_HDRLEN 4

#define MAX_EXT_DATA_LEN				256
#define ALPN_EXT_TYPE					0x0010
#define SERVER_NAME_EXT_TYPE			0x0000
#define SERVER_NAME_HOST_TYPE 			0x0000
#define SERVER_NAME_OTHER_TYPE 			0x0008
#define SESSION_TICKET_EXT_TYPE 		0x0023
#define ENCRPTED_SERVER_NAME_EXT_TYPE	0xFFCE
#define ENCRPTED_CLIENT_HELLO_EXT_TYPE	0xFE0D

#define CERTIFICATE_HDRLEN		7
#define SSL_CERTIFICATE_HDRLEN  3

extern int ja3_md5sum(const char *str, int len, char *buf, int size);
extern struct ssl_serial_string g_astCipherSuit;

const struct ssl_serial_string g_astCompression[] =
	{
		{{0}, NULL},
};

const struct ssl_value2string ssl_version_list[] =
{
    { DTLSV1_0_VERSION, 	"DTLS1.0" },
    { DTLSV1_0_VERSION_NOT, "DTLS1.0(OpenSSL pre 0.9.8f)" },  
    { TLSV1_2_VERSION, 		"TLS1.2" },
    { TLSV1_1_VERSION, 		"TLS1.1" },
    { TLSV1_0_VERSION, 		"TLS1.0" },
    { SSLV3_VERSION, 		"SSL3.0" },
    { SSLV2_VERSION, 		"SSL2.0" },
    { UNKNOWN_VERSION, 		NULL }
};

const char *ssl_get_suite(struct ssl_l2v *ciphersuites)
{
	if (ciphersuites == NULL)
		return NULL;
	return fn_pcGetSuite((unsigned char *)ciphersuites->value, ciphersuites->len, (struct ssl_serial_string *)&g_astCipherSuit);
}


int ssl_parse_lv1(struct ssl_l1v *lv1, unsigned char *payload, int payload_len)
{
	lv1->len=(unsigned char)BtoL1BytesNum((const char *)payload);
	int offset=(int)sizeof(lv1->len);
	if((payload_len-offset-lv1->len)<0)
	{
		return -1;
	}

	if(lv1->len>0)
	{
		lv1->value=payload+offset;
		offset+=lv1->len;
	}

	return offset;
}

int ssl_parse_lv2(struct ssl_l2v *lv2, unsigned char *payload, int payload_len)
{
	lv2->len=(unsigned short)BtoL2BytesNum((const char *)payload);
	int offset=sizeof(lv2->len);
	if((payload_len-offset-(lv2->len))<0)
	{
		return -1;
	}

	if(lv2->len>0)
	{
		lv2->value=payload+offset;
		offset+=lv2->len;
	}

	return offset;
}

int ssl_parse_ltv2(struct ssl_l2tv *ltv2, unsigned char *payload, int payload_len)
{
	ltv2->type=(unsigned short)BtoL2BytesNum((const char *)(payload));
	int offset=(int)sizeof(ltv2->type);
	if((payload_len-offset)<0)
	{
		return -1;
	}

	ltv2->len=(unsigned short)BtoL2BytesNum((const char *)(payload+offset));
	offset+=(int)sizeof(ltv2->len);
	if((payload_len-offset-ltv2->len)<0)
	{
		return -1;
	}

	if(ltv2->len>0)
	{
		ltv2->value=payload+offset;
		offset+=ltv2->len;
	}

	return offset;
}

void ssl_trunk_free(struct ssl_runtime_context *ssl_context, int thread_seq)
{
	if(ssl_context!=NULL)
	{
		if(ssl_context->record.cache_buff!=NULL)
		{
			dictator_free(thread_seq, ssl_context->record.cache_buff);
			ssl_context->record.cache_buff=NULL;
		}
		
		ssl_context->record.cache_len=0;
	}
}

int ssl_trunk_cache(struct ssl_runtime_context *ssl_context, char *payload, int payload_len, int thread_seq)
{
	if(ssl_context->record.cache_buff==NULL)
	{
		ssl_context->record.cache_buff=(char *)dictator_malloc(thread_seq, g_ssl_runtime_para.max_cache_len);
	}

	ssl_context->record.cache_len=0;
	int length=MIN(payload_len, g_ssl_runtime_para.max_cache_len);
	memcpy(ssl_context->record.cache_buff+ssl_context->record.cache_len, payload, length);
	ssl_context->record.cache_len+=length;

	return 0;
}

int ssl_get_alpn_list(struct ssl_l2tv *extension_alpn, struct ssl_alpn_list* alpn_list, int alpn_size)
{
	if(extension_alpn==NULL || (extension_alpn->value==NULL) || (extension_alpn->len==0) || (extension_alpn->type!=ALPN_EXT_TYPE))
	{
		return 0;
	}

	int alpn_proto_num = 0;	
	unsigned char* alpl=extension_alpn->value;
	int alpn_ext_len=BtoL2BytesNum((char *)alpl);
	if(alpn_ext_len<=0 || alpn_ext_len>extension_alpn->len)
	{
		return 0;
	}

	alpl+=2;
	while(alpn_ext_len>0 && alpn_proto_num<alpn_size)
	{
		int alpn_proto_len = BtoL1BytesNum((char *)alpl);
		alpl++;
		alpn_ext_len-=1;

		alpn_list[alpn_proto_num].alpn=(char*)alpl;
		alpn_list[alpn_proto_num].alpn_len=alpn_proto_len;
		alpn_ext_len-=alpn_proto_len;
		alpl+=alpn_proto_len;
		alpn_proto_num++;
	}	
	
	return alpn_proto_num;
}

unsigned short ssl_get_hello_version(unsigned char *pcData, unsigned int payload_len)
{
	if (CLIENT_HELLO != pcData[0] && SERVER_HELLO != pcData[0])
	{
		return 0;
	}

	if (03 == pcData[4] && 1 == pcData[5])
	{
		/*TLS 1.0*/
		return TLSV1_0_VERSION;
	}
	else if (03 == pcData[4] && 2 == pcData[5])
	{
		/*TLS 2.0*/
		return TLSV1_1_VERSION;
	}
	else if (03 == pcData[4] && 3 == pcData[5])
	{
		/*TLS 2.0*/
		return TLSV1_2_VERSION;
	}
	else if (03 == pcData[4] && 0 == pcData[5])
	{
		/*SSL 3.0*/
		return SSLV3_VERSION;
	}
	else if (0 == pcData[4] && 2 == pcData[5])
	{
		/*SSL 2.0*/
		return SSLV2_VERSION;
	}
	else if (0xfe == (unsigned char)pcData[4] && 0xff == (unsigned char)pcData[5])
	{
		/*DTLS 1.0*/
		return DTLSV1_0_VERSION;
	}
	else if (0x01 == (unsigned char)pcData[4] && 0x00 == (unsigned char)pcData[5])
	{
		/*DTLS 1.0 (OpenSSL pre 0.9.8f)*/
		return DTLSV1_0_VERSION_NOT;
	}
	return 0;
}

int ssl_parse_server_name(struct ssl_client_hello *chello, struct ssl_l2tv *extension)
{
	struct client_server_name p_server_name={0};

	p_server_name.list_len=extension->len;
	unsigned char *cur_data=extension->value;

	p_server_name.list_len-=sizeof(p_server_name.list_len);
	cur_data+=sizeof(p_server_name.list_len);

	/*3=sizeof(p_server_name.server_name_type)+sizeof(p_server_name.server_name_len)*/
	while(p_server_name.list_len>3)
	{				
		p_server_name.type = BtoL1BytesNum((const char *)cur_data);
		p_server_name.len = BtoL2BytesNum((const char *)(cur_data+1));
		p_server_name.list_len -= 3;
		cur_data += 3;
		/*have data*/
		if(((p_server_name.type == SERVER_NAME_HOST_TYPE)) && p_server_name.len>0&& p_server_name.list_len>=p_server_name.len)
		{
			p_server_name.data = cur_data;

			int length=MIN(sizeof(chello->server_name)-1, p_server_name.len);
			memcpy(chello->server_name, p_server_name.data, length);
			chello->server_name[length]='\0';
			break;
		}
		p_server_name.list_len-=p_server_name.len;
		cur_data+=p_server_name.len;
	}

	return 0;
}

int ssl_parse_encrypt_server_name(struct ssl_client_hello *chello, struct ssl_l2tv *extension)
{
	int offset=0,one_l2v=0;
	unsigned char* cur_data=extension->value;
	int extension_len=extension->len;
	
	if(extension_len-offset>SUITE_VALUELEN)
	{
		chello->esni.suite.value=cur_data+offset;
		chello->esni.suite.len=SUITE_VALUELEN;
		offset+=SUITE_VALUELEN;
	}
	
	if((extension_len-offset)>=(int)sizeof(chello->esni.key_exchange_group))
	{
		chello->esni.key_exchange_group=(unsigned short)BtoL2BytesNum((const char *)(cur_data+offset));
		offset+=sizeof(chello->esni.key_exchange_group);
	}
	else
	{
		return 0;
	}
	
	one_l2v=ssl_parse_lv2(&(chello->esni.key_exchange), cur_data+offset, extension_len-offset);
	if(one_l2v==-1)
	{
		return 0;
	}

	offset+=one_l2v;
		
	one_l2v=ssl_parse_lv2(&(chello->esni.record_digest), cur_data+offset, extension_len-offset);
	if(one_l2v==-1)
	{
		return 0;
	}
	offset+=one_l2v;

	one_l2v=ssl_parse_lv2(&(chello->esni.esni), cur_data+offset, extension_len-offset);
	if(one_l2v==-1)
	{
		return 0;
	}
	offset+=one_l2v;

	chello->esni.is_esni=1;

	return 1;
}

int ssl_parse_client_hello(struct ssl_client_hello *chello, unsigned char *payload, int payload_len)
{
	int offset=0,one_ltv=0;
	chello->total_len=BtoL3BytesNum((const char *)(payload+1));
	if(chello->total_len<0) /*CLIENT_HELLO_HDRLEN: 4 means client_type+len*/
	{
		return SSL_FLASE;
	}

	if((chello->total_len+CLIENT_HELLO_HDRLEN > payload_len) || (chello->total_len-(int)sizeof(chello->version)<0))
	{
		return SSL_FLASE;
	}

	chello->version=ssl_get_hello_version((unsigned char *)payload, payload_len);
	if(chello->version==0)
	{
		return SSL_FLASE;
	}

	offset+=(CLIENT_HELLO_HDRLEN+sizeof(chello->version));

	/*get client hello random*/
	chello->random.gmt_time=(unsigned int)BtoL4BytesNum((const char *)(payload+offset));
	offset+=sizeof(chello->random.gmt_time);
	
	if(payload_len-offset-SSL_RANDOM_SIZE<=0)
	{
		return SSL_FLASE;
	}
	
	chello->random.bytes.len=SSL_RANDOM_SIZE;
	chello->random.bytes.value=payload+offset;
	offset+=SSL_RANDOM_SIZE;

	/*get client hello session*/
	one_ltv=ssl_parse_lv1(&(chello->session), payload+offset, payload_len-offset);
	if(one_ltv==-1)
	{
		return SSL_FLASE;
	}
	offset+=one_ltv;
	
	/*get client hello suites*/
	one_ltv=ssl_parse_lv2(&chello->ciphersuites, payload+offset, payload_len-offset);
	if(one_ltv==-1)
	{
		return SSL_FLASE;
	}
	offset+=one_ltv;

	/*get client hello compress*/
	one_ltv=ssl_parse_lv1(&(chello->compress_method), payload+offset, payload_len-offset);
	if(one_ltv==-1)
	{
		return SSL_FLASE;
	}
	offset+=one_ltv;

	/*get extension*/
	chello->extensions.len=(unsigned short)BtoL2BytesNum((const char *)(payload+offset));
	offset+=sizeof(chello->extensions.len);

	for(int i=0; payload_len-offset >= 4 && i < MAX_EXTENSION_NUM; i++) // min len of ext is 4 byte
	{
		one_ltv=ssl_parse_ltv2(&(chello->extensions.extension[i]), payload+offset, payload_len-offset);
		if(one_ltv==-1)
		{
			return SSL_FLASE;
		}
		offset+=one_ltv;
		chello->extensions.num++;

		switch(chello->extensions.extension[i].type)
		{
			case	SERVER_NAME_EXT_TYPE:
				ssl_parse_server_name(chello, &(chello->extensions.extension[i]));
				break;
			case	SESSION_TICKET_EXT_TYPE:
				chello->session_ticket=&(chello->extensions.extension[i]);
				break;
			case	ENCRPTED_SERVER_NAME_EXT_TYPE:
				ssl_parse_encrypt_server_name(chello, &(chello->extensions.extension[i]));
				break;
			case	ENCRPTED_CLIENT_HELLO_EXT_TYPE:
				chello->encrypt_chello=&(chello->extensions.extension[i]);
				break;
			case	ALPN_EXT_TYPE:
				chello->alpn=&(chello->extensions.extension[i]);
				break;
			default:
				break;
		}
	}

	return SSL_TRUE;
}

int ssl_parse_server_hello(struct ssl_server_hello *shello, unsigned char *payload, int payload_len)
{
	int offset=0,one_ltv=0;
	int ja3s_string_offset=0;
	char ja3s_string[1024]={0};
	shello->total_len = BtoL3BytesNum((const char *)(payload+1));
	if(shello->total_len<0 || (shello->total_len+SERVER_HELLO_HDRLEN > payload_len-offset))
	{
		return SSL_FLASE;
	}

	shello->version=ssl_get_hello_version((unsigned char *)payload, payload_len-offset);
	if(shello->version==0)
	{
		return SSL_FLASE;
	}
	
	ja3s_string_offset+=snprintf(ja3s_string+ja3s_string_offset, sizeof(ja3s_string)-ja3s_string_offset, "%u,", shello->version);

	offset+=(sizeof(shello->version)+SERVER_HELLO_HDRLEN);

	/*get client hello random*/
	shello->random.gmt_time=(unsigned int)BtoL4BytesNum((const char *)(payload+offset));
	offset+=sizeof(shello->random.gmt_time);
	
	if(payload_len-offset-SSL_RANDOM_SIZE<=0)
	{
		return SSL_FLASE;
	}
	
	shello->random.bytes.len=SSL_RANDOM_SIZE;
	shello->random.bytes.value=payload+offset;
	offset+=SSL_RANDOM_SIZE;

	/*get client hello session*/
	one_ltv=ssl_parse_lv1(&(shello->session), payload+offset, payload_len-offset);
	if(one_ltv==-1)
	{
		return SSL_FLASE;
	}
	offset+=one_ltv;
	
	/*get client hello suites*/
	shello->ciphersuites.len=2;
	shello->ciphersuites.value=payload+offset;
	offset+=2;
	
	ja3s_string_offset+=snprintf(ja3s_string+ja3s_string_offset, sizeof(ja3s_string)-ja3s_string_offset, "%u,", ntohs(*(unsigned short *)(shello->ciphersuites.value)));

	/*get client hello compress*/
	shello->compress_method.len=1;
	shello->compress_method.value=payload+offset;
	offset+=1;

	/*get extension*/
	shello->extensions.len=(unsigned short)BtoL2BytesNum((const char *)(payload+offset));
	offset+=sizeof(shello->extensions.len);

	// shello->total_len not contains handshake header
	for(int i=0; (shello->total_len-offset+SERVER_HELLO_HDRLEN) >=4 && i < MAX_EXTENSION_NUM; i++) // min len of ext is 4 byte
	{
		one_ltv=ssl_parse_ltv2(&(shello->extensions.extension[i]), payload+offset, payload_len-offset);
		if(one_ltv==-1)
		{
			return SSL_FLASE;
		}
		offset+=one_ltv;
		shello->extensions.num++;

		ja3s_string_offset+=snprintf(ja3s_string+ja3s_string_offset, sizeof(ja3s_string)-ja3s_string_offset, "%u-", shello->extensions.extension[i].type);
	}

	ja3s_string_offset--;
	if(ja3s_string_offset==0)
	{
		return SSL_FLASE;		
	}

	ja3s_string[ja3s_string_offset]='\0';
	shello->ja3s.fingerprint_md5_len=ja3_md5sum(ja3s_string, ja3s_string_offset, shello->ja3s.fingerprint_md5, sizeof(shello->ja3s.fingerprint_md5));
	shello->ja3s.fingerprint_md5[shello->ja3s.fingerprint_md5_len]='\0';
	
	return SSL_TRUE;
}

int ssl_parse_new_session_ticket(struct ssl_new_session_ticket *new_session_ticket, char *payload, int payload_len)
{
	int offset=0;
	new_session_ticket->total_len=BtoL3BytesNum((const char *)(payload+1));
	if(new_session_ticket->total_len<0)
	{
		return SSL_FLASE;
	}
	
	/*4 means _type+len*/
	if(new_session_ticket->total_len+SESSION_TICKET_HDRLEN > payload_len-offset)
	{
		/**packet trunked**/
		return SSL_FLASE;
	}
	offset+=SESSION_TICKET_HDRLEN;
	new_session_ticket->lift_time=BtoL4BytesNum((const char *)(payload+offset));
	offset+=sizeof(new_session_ticket->lift_time);
	new_session_ticket->ticket_len=BtoL2BytesNum((const char *)(payload+offset));
	
	new_session_ticket->ticket=(unsigned char *)(payload+offset);

	return SSL_TRUE;
}

int ssl_parse_certificate_detail(const struct streaminfo *a_tcp, struct ssl_runtime_context *ssl_context, char *payload, int payload_len, int thread_seq, const void *a_packet)
{
	if(!(g_ssl_runtime_para.ssl_interested_region_flag&SSL_CERTIFICATE_DETAIL))
	{
		ssl_context->stream.certificate=NULL;
		return SSL_TRUE;
	}
	
	int	certificate_num=0;
	struct ssl_certificate_chain cert_unit[CERT_MAXNUM];
	int certificate_count=ssl_read_all_cert(payload, payload_len, cert_unit, CERT_MAXNUM);

	for(int i=0;i<certificate_count;i++)
	{
		int state=x509_parse_certificate_detail(ssl_context->stream.certificate, cert_unit[i].cert, cert_unit[i].cert_len, thread_seq);
		if(state==SSL_FLASE)
		{
			return SSL_FLASE;
		}

		ssl_context->stream.certificate->cert_len = cert_unit[i].cert_len;

		switch(certificate_num)
		{
			case 0:
				ssl_context->stream.certificate->cert_type=CERT_TYPE_INDIVIDUAL;
				break;
			case 1:
				if(certificate_count==2)
				{
					ssl_context->stream.certificate->cert_type=CERT_TYPE_ROOT;
				}
				else
				{
					ssl_context->stream.certificate->cert_type=CERT_TYPE_MIDDLE;
				}
				break;
			case 2:
				if(certificate_count==3)
				{
					ssl_context->stream.certificate->cert_type=CERT_TYPE_ROOT;
				}
				else
				{
					ssl_context->stream.certificate->cert_type=CERT_TYPE_CHAIN;
				}
				break;			
			default:
				if(certificate_num==certificate_count-1)
				{
					ssl_context->stream.certificate->cert_type=CERT_TYPE_ROOT;
				}
				else
				{
					ssl_context->stream.certificate->cert_type=CERT_TYPE_CHAIN;
				}
				break;
		}

		ssl_call_plugins(a_tcp, ssl_context, (char *)(ssl_context->stream.certificate), sizeof(struct ssl_certificate), SSL_CERTIFICATE_DETAIL_MASK, thread_seq, a_packet);
		certificate_num++;

		ssl_context->stream.certificate->subject_alter.num=0;
		if(ssl_context->stream.certificate->subject_alter.name!=NULL)
		{
			dictator_free(thread_seq, ssl_context->stream.certificate->subject_alter.name);
			ssl_context->stream.certificate->subject_alter.name=NULL;
		}

		ssl_context->stream.certificate->subject_key.len=0;
		if(ssl_context->stream.certificate->subject_key.value!=NULL)
		{
			dictator_free(thread_seq, ssl_context->stream.certificate->subject_key.value);
			ssl_context->stream.certificate->subject_key.value=NULL;
		}
	
		memset(&(ssl_context->stream.certificate->issuer), 0, sizeof(struct ssl_rdn_sequence));
		memset(&(ssl_context->stream.certificate->subject), 0, sizeof(struct ssl_rdn_sequence));
		
		ssl_context->stream.certificate->serial.len=0;
		ssl_context->stream.certificate->version.len=0;
		ssl_context->stream.certificate->version.value=NULL;
		ssl_context->stream.certificate->validity.before[0]='\0';
		ssl_context->stream.certificate->validity.after[0]='\0';
		ssl_context->stream.certificate->signature_algorithm.len=0;
		ssl_context->stream.certificate->signature_algorithm.value[0]='\0';
	}

	return SSL_TRUE;
}

int ssl_parse_certificate(const struct streaminfo *a_tcp, struct ssl_runtime_context *ssl_context, char *payload, int payload_len, int thread_seq, const void *a_packet)
{
	int offset=0;
	
	ssl_context->stream.certificate->total_len=BtoL3BytesNum((const char *)(payload+4));
	if(ssl_context->stream.certificate->total_len<0)
	{
		return SSL_FLASE;
	}

	/*7 means cert_type+len*/
	if(ssl_context->stream.certificate->total_len+CERTIFICATE_HDRLEN>payload_len)
	{
		/**packet trunked**/
		return SSL_TRUE;
	}

	/*2 means version*/
	offset=CERTIFICATE_HDRLEN;

	if(g_ssl_runtime_para.ssl_interested_region_flag & SSL_CERTIFICATE)
	{
		ssl_call_plugins(a_tcp, ssl_context, payload+offset, payload_len-offset, SSL_CERTIFICATE_MASK, thread_seq, a_packet);
	}

	return ssl_parse_certificate_detail(a_tcp, ssl_context, payload+offset, payload_len-offset, thread_seq, a_packet);
}

int ssl_parse_handshake(const struct streaminfo *a_tcp, struct ssl_runtime_context *ssl_context, char *payload, int payload_len, int thread_seq, const void *a_packet)
{
	int offset=0;
	int state=SSL_TRUE;
	
	while((payload_len-offset) > 0)
	{
		struct ssl_handshake_type *handshake=(struct ssl_handshake_type *)(payload+offset);
		if(CERTIFICATE == handshake->content_type)
		{
			if(payload_len-offset<CERTIFICATE_HDRLEN)
			{
				/**packet trunked**/
				break;
			}
			
			struct ssl_certificate certificate={0};
			ssl_context->stream.certificate=&certificate;
			state=ssl_parse_certificate(a_tcp, ssl_context, payload+offset, payload_len-offset, thread_seq, a_packet);
			if(state!=SSL_TRUE)
			{
				return state;
			}
			offset+=(certificate.total_len+CERTIFICATE_HDRLEN);
			ssl_context->stream.certificate=NULL;
		}
		/**analyse client_hello**/
		else if (CLIENT_HELLO == handshake->content_type)
		{
			if ((payload_len-offset)<CLIENT_HELLO_HDRLEN)
			{
				break;
			}

			struct ssl_client_hello chello={0};
			ssl_context->stream.chello=&chello;
			state=ssl_parse_client_hello(&chello, (unsigned char *)(payload+offset), payload_len-offset);
			if(state!=SSL_TRUE)
			{
				return state;
			}

			ssl_call_plugins(a_tcp, ssl_context, (char *)(payload+offset), chello.total_len+CLIENT_HELLO_HDRLEN, SSL_CLIENT_HELLO_MASK, thread_seq, a_packet);
			offset+=(chello.total_len+CLIENT_HELLO_HDRLEN);
			ssl_context->stream.chello=NULL;
		}
		/**analyse server_hello**/
		else if (SERVER_HELLO == handshake->content_type)
		{
			if((payload_len-offset)<SERVER_HELLO_HDRLEN)
			{
				break;
			}

			struct ssl_server_hello shello={0};
			ssl_context->stream.shello=&shello;
			state=ssl_parse_server_hello(&shello, (unsigned char *)(payload+offset), payload_len-offset);
			if(state!=SSL_TRUE)
			{
				return state;
			}
			
			ssl_call_plugins(a_tcp, ssl_context, (char *)(payload+offset), shello.total_len+SERVER_HELLO_HDRLEN, SSL_SERVER_HELLO_MASK, thread_seq, a_packet);
			offset+=(shello.total_len+SERVER_HELLO_HDRLEN);
			ssl_context->stream.shello=NULL;
		}
		else if (NEW_SESSION_TICKET == handshake->content_type)
		{
			if((payload_len-offset) < SESSION_TICKET_HDRLEN)
			{
				break;
			}
			struct ssl_new_session_ticket new_session_ticket={0};
			ssl_context->stream.new_session_ticket=&new_session_ticket;
			state=ssl_parse_new_session_ticket(&new_session_ticket, (payload+offset), (payload_len-offset));
			if(state!=SSL_TRUE)
			{
				return state;
			}

			ssl_call_plugins(a_tcp, ssl_context, (char *)(payload+offset), new_session_ticket.total_len+SESSION_TICKET_HDRLEN, SSL_NEW_SESSION_TICKET_MASK, thread_seq, a_packet);
			offset+=(new_session_ticket.total_len+SESSION_TICKET_HDRLEN);
			ssl_context->stream.new_session_ticket=NULL;
		}
		else
		{
			break;
		}
	}

	return SSL_TRUE;;
}

int ssl_parse_application_data(const struct streaminfo *a_tcp, struct ssl_runtime_context *ssl_context, char *payload, int payload_len, int thread_seq, const void *a_packet)
{
	if (NULL==payload || payload_len<= 0)
	{
		return SSL_TRUE;
	}

	ssl_call_plugins(a_tcp, ssl_context, payload, payload_len, SSL_APPLICATION_DATA_MASK, thread_seq, a_packet);
	return SSL_TRUE;
}

int ssl_parse_alert(const struct streaminfo *a_tcp, struct ssl_runtime_context *ssl_context, char *payload, int payload_len, int thread_seq, const void *a_packet)
{
	if(NULL==payload || payload_len<=0)
	{
		return SSL_TRUE;
	}

	ssl_call_plugins(a_tcp, ssl_context, payload, payload_len, SSL_ALERT_MASK, thread_seq, a_packet);
	return SSL_TRUE;
}

int ssl_identify_version(char *pcData, int payload_len)
{
	if (NULL == pcData || payload_len < 1)
	{
		return 0;
	}
	else if (20 > pcData[0] || 23 < pcData[0])
	{
		return 0;
	}

	if (03 == pcData[1] && 1 == pcData[2])
	{
		/*TLS 1.0*/
		return TLSV1_0_VERSION;
	}
	else if (03 == pcData[1] && 2 == pcData[2])
	{
		/*TLS 1.1*/
		return TLSV1_1_VERSION;
	}
	else if (03 == pcData[1] && 3 == pcData[2])
	{
		/*TLS 1.2*/
		return TLSV1_2_VERSION;
	}
	else if (03 == pcData[1] && 0 == pcData[2])
	{
		/*SSL 3.0*/
		return SSLV3_VERSION;
	}
	else if (0 == pcData[1] && 2 == pcData[2])
	{
		/*SSL 2.0*/
		return SSLV2_VERSION;
	}
	else if (0xfe == (unsigned char)pcData[1] && 0xff == (unsigned char)pcData[2])
	{
		/*DTLS 1.0*/
		return DTLSV1_0_VERSION;
	}
	else if (0x01 == (unsigned char)pcData[1] && 0x00 == (unsigned char)pcData[2])
	{
		/*DTLS 1.0 (OpenSSL pre 0.9.8f)*/
		return DTLSV1_0_VERSION_NOT;
	}

	return 0;
}

const char* ssl_get_version_name(unsigned short version)
{	
	for(unsigned int i=0;ssl_version_list[i].value!=0;i++)
	{
		if(ssl_version_list[i].value==version)
		{
			return (char*)ssl_version_list[i].string;
		}
	}
	
	return NULL;
}

int ssl_parse_version(const struct streaminfo *a_tcp, struct ssl_runtime_context *ssl_context, char *payload, int payload_len, int thread_seq, const void *a_packet)
{
	if(UNKNOWN_VERSION==ssl_context->version)
	{
		ssl_context->version=(unsigned int)ssl_identify_version(payload, payload_len);
		/*jump the first pkt*/
		if (UNKNOWN_VERSION==ssl_context->version)
		{
			if (ssl_context->first_pkt_flag==0)
			{
				ssl_context->first_pkt_flag=1;
				return SSL_CONTINUE;
			}
			else
			{
				return SSL_FLASE;
			}
		}
		/*version callback*/
		for(int i=0; ssl_version_list[i].value!=0; i++)
		{
			if(ssl_version_list[i].value==ssl_context->version)
			{
				ssl_call_plugins(a_tcp, ssl_context, (char*)ssl_version_list[i].string, strlen(ssl_version_list[i].string), SSL_VERSION_MASK, thread_seq, a_packet);
				break;
			}
		}	
	}

	return SSL_TRUE;
}

int ssl_parse_message(const struct streaminfo *a_tcp, struct ssl_runtime_context *ssl_context, char *payload, int payload_len, int thread_seq, const void *a_packet)
{
	int offset=0;
	int state=SSL_TRUE;

	state=ssl_parse_version(a_tcp, ssl_context, payload, payload_len, thread_seq, a_packet);
	if(state!=SSL_TRUE)
	{
		return state;
	}

	while(payload_len-offset > SSL_RECORD_HDRLEN)
	{
		struct ssl_record_header *ssl_record=(struct ssl_record_header *)(payload+offset);
		
		int one_record_len=htons(ssl_record->total_len);
		ssl_context->is_ssl_stream=SSL_TRUE;
		
		if((payload_len-offset) < one_record_len)
		{
			ssl_trunk_cache(ssl_context, payload+offset, payload_len-offset, thread_seq);
			break; //cache
		}
		
		offset+=SSL_RECORD_HDRLEN;
		
		switch (ssl_record->content_type)
		{
			case APPLICATION_DATA:
				state=ssl_parse_application_data(a_tcp, ssl_context, payload+offset, one_record_len, thread_seq, a_packet);
				break;
			case ALERT:	
				state=ssl_parse_alert(a_tcp, ssl_context, payload+offset, one_record_len, thread_seq, a_packet);
				break;
			case HANDSHAKE:
				state=ssl_parse_handshake(a_tcp, ssl_context, payload+offset, one_record_len, thread_seq, a_packet);
				break;
			case CHANGE_CIPHER_SEP:
				break;
			default:
				if (ssl_context->is_ssl_stream==SSL_TRUE)
				{
					return SSL_TRUE;
				}
				else
				{
					return SSL_FLASE;
				}
		}

		if(state==SSL_FLASE)
		{
			offset=payload_len;
			break;
		}

		offset+=one_record_len;
	}

	if(offset==payload_len)
	{
		ssl_trunk_free(ssl_context, thread_seq);
	}

	return state;
}

int ssl_parse_stream(const struct streaminfo *a_tcp, struct ssl_runtime_context *ssl_context, int thread_seq, const void *a_packet)
{
	int payload_len = 0;
	char *payload=NULL;

	if(ssl_context==NULL)
	{
		return SSL_FLASE;
	}

	struct tcpdetail *tcp_detail=(struct tcpdetail *)a_tcp->pdetail;

	/**if buffered, copy new data to the buff**/
	/**if lose packets, drop the buffered data**/
	/*bad data fill the buffer,  or lose pkt clear it*/
	if(tcp_detail->lostlen>0 && ssl_context->record.cache_len>0)
	{
		ssl_trunk_free(ssl_context, thread_seq);
	}

	if(ssl_context->record.cache_len>0)
	{
		payload_len=MIN((int)tcp_detail->datalen, (g_ssl_runtime_para.max_cache_len - ssl_context->record.cache_len));
		memcpy(ssl_context->record.cache_buff + ssl_context->record.cache_len, tcp_detail->pdata, payload_len);
		ssl_context->record.cache_len += payload_len;
		payload_len=ssl_context->record.cache_len;
		payload=ssl_context->record.cache_buff;
	}
	else
	{
		payload=(char *)tcp_detail->pdata;
		payload_len=tcp_detail->datalen;
	}

	/**validaty check**/
	if(NULL==payload || payload_len<SSL_HEADER_LEN)
	{
		return SSL_TRUE;
	}

	return ssl_parse_message(a_tcp, ssl_context, payload, payload_len, thread_seq, a_packet);
}
