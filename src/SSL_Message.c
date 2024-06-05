
#include "SSL_Analyze.h"
#include "ssl.h"
#include "SSL_Message.h"
#include "SSL_Proc.h"
#include "SSL_Common.h"
#include "SSL_Certificate.h"

extern ssl_prog_runtime_parameter_t g_ssl_prog_para;
extern stSerialString_t g_astCipherSuit;

const stSerialString_t g_astCompression[] =
	{
		{{0}, NULL},
};

const char *ssl_get_suite(st_suites_t *ciphersuites)
{
	if (ciphersuites == NULL)
		return NULL;
	return fn_pcGetSuite((unsigned char *)ciphersuites->suites_value, ciphersuites->suites_len, (stSerialString_t *)&g_astCipherSuit);
}

unsigned short ssl_getHelloVersion(unsigned char *pcData, unsigned int iDataLen)
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

int fn_iIsHandShakeMsg(unsigned char ucMsgType)
{
	switch (ucMsgType)
	{
		//        case HELLO_REQUEST:
	case CLIENT_HELLO:
	case SERVER_HELLO:
	case CERTIFICATE:
	case NEW_SESSION_TICKET:
		//        case SERVER_KEY_EXCHANGE:
		//        case CERTIFICATE_REQUEST:
		//        case SERVER_HELLO_DONE:
		//        case CERTIFICATE_VERIFY:
		//        case CLIENT_KEY_EXCHANGE:
		//        case FINISHED:
		return 1;
		break;
	default:
		return 0;
		break;
	}
}

/*
Function: analyse ssl hand shake msgs
Note:       if one msg is trunked, just wait
return : SSL_RETURN_UNNORM : error ; SSL_RETURN_DROPME/KILLME; business return_value
*/
UCHAR ssl_analyseHandShake(char *pcSslData, int iAllMsgLen, int iSslUnAnalyseLen, int *res, ssl_stream *a_ssl_stream, struct streaminfo *a_tcp,
						   unsigned long long region_flag, int thread_seq, void *a_packet)
{
	/**variable define and initialise**/
	int iSslDataLen = 0;
	char *pcCurSslData=NULL;
	int iUnAnalyseLen;
	int iUnAnaCertLen;
	int iUnAnaHelloLen;
	UCHAR return_val;
	stHandShakeTypeHdr_t *pstHandShakeTypeHdr = NULL;

	iSslDataLen = iAllMsgLen < iSslUnAnalyseLen ? iAllMsgLen : iSslUnAnalyseLen;
	iUnAnalyseLen = iAllMsgLen < iSslUnAnalyseLen ? iAllMsgLen : iSslUnAnalyseLen;

	while (iUnAnalyseLen > 0)
	{

		// 20150324
		pstHandShakeTypeHdr = (stHandShakeTypeHdr_t *)pcSslData;
		pcCurSslData = pcSslData;
		/**analyse certification**/
		if (CERTIFICATE == pstHandShakeTypeHdr->ucContType)
		{
			if (iUnAnalyseLen < CERTIFICATE_HDRLEN)
			{
				/**packet trunked**/
				break;
			}

			if (a_ssl_stream->stSSLCert == NULL)
			{
				a_ssl_stream->stSSLCert = (st_cert_t *)dictator_malloc(thread_seq, sizeof(st_cert_t));
				// memset(a_ssl_stream->stSSLCert, 0, sizeof(a_ssl_stream->stSSLCert));
			}
			memset(a_ssl_stream->stSSLCert, 0, sizeof(st_cert_t));
			a_ssl_stream->stSSLCert->totallen = BtoL3BytesNum((char *)(pcCurSslData + 4));
			if (a_ssl_stream->stSSLCert->totallen < 0)
				return SSL_RETURN_DROPME;

			/*7 means cert_type+len*/
			if (a_ssl_stream->stSSLCert->totallen + 7 > iUnAnalyseLen)
			{
				/**packet trunked**/
				break;
			}

			/*2 means version*/
			pcCurSslData += CERTIFICATE_HDRLEN;
			iUnAnaCertLen = iUnAnalyseLen - CERTIFICATE_HDRLEN;

			if (g_ssl_prog_para.ssl_interested_region_flag & SSL_CERTIFICATE)
			{
				a_ssl_stream->p_output_buffer->p_data = pcCurSslData;
				a_ssl_stream->p_output_buffer->data_size = iUnAnaCertLen;
				a_ssl_stream->output_region_mask = SSL_CERTIFICATE_MASK;
				return_val = ssl_doWithCertificate(&a_ssl_stream, a_tcp, region_flag, thread_seq, a_packet);
				a_ssl_stream->p_output_buffer->p_data = NULL;
				a_ssl_stream->p_output_buffer->data_size = 0;
				if (SSL_RETURN_NORM != return_val)
					return return_val;
			}
			if (g_ssl_prog_para.ssl_interested_region_flag & SSL_CERTIFICATE_DETAIL)
			{
				return_val = ssl_AnalyseCertificate(pcCurSslData, iUnAnaCertLen, a_ssl_stream, a_tcp, region_flag, thread_seq, a_packet);
				if (SSL_RETURN_NORM != return_val)
					return return_val;
			}
			iUnAnalyseLen -= (a_ssl_stream->stSSLCert->totallen + 7);
			pcSslData += (a_ssl_stream->stSSLCert->totallen + 7);
		}
		/**analyse client_hello**/
		else if (CLIENT_HELLO == pstHandShakeTypeHdr->ucContType)
		{
			if (iUnAnalyseLen < CLIENT_HELLO_HDRLEN)
			{
				break;
			}
			if (a_ssl_stream->stClientHello == NULL)
			{
				a_ssl_stream->stClientHello = (st_client_hello_t *)dictator_malloc(thread_seq, sizeof(st_client_hello_t));
				memset(a_ssl_stream->stClientHello, 0, sizeof(st_client_hello_t));
				ssl_initStructClientHello(a_ssl_stream->stClientHello);
			}

			a_ssl_stream->stClientHello->totallen = BtoL3BytesNum((char *)(pcCurSslData + 1));
			if (a_ssl_stream->stClientHello->totallen < 0)
				return SSL_RETURN_DROPME;

			/*4 means client_type+len*/
			if (a_ssl_stream->stClientHello->totallen + CLIENT_HELLO_HDRLEN > iUnAnalyseLen)
			{
				/**packet trunked**/
				break;
			}
			if (0 == (a_ssl_stream->stClientHello->client_ver = ssl_getHelloVersion((unsigned char *)pcCurSslData, iUnAnalyseLen)))
			{
				return SSL_RETURN_DROPME;
			}

			iUnAnaHelloLen = a_ssl_stream->stClientHello->totallen - sizeof(a_ssl_stream->stClientHello->client_ver);
			if (iUnAnaHelloLen < 0)
			{
				return SSL_RETURN_DROPME;
			}
			pcCurSslData += CLIENT_HELLO_HDRLEN + sizeof(a_ssl_stream->stClientHello->client_ver);

			/*get client hello random*/
			a_ssl_stream->stClientHello->random.gmt_time = (unsigned int)BtoL4BytesNum(pcCurSslData);
			pcCurSslData += sizeof(a_ssl_stream->stClientHello->random.gmt_time);
			iUnAnaHelloLen -= sizeof(a_ssl_stream->stClientHello->random.gmt_time);
			if (iUnAnaHelloLen < 0)
			{
				return SSL_RETURN_DROPME;
			}
			memcpy(a_ssl_stream->stClientHello->random.random_bytes, pcCurSslData, sizeof(a_ssl_stream->stClientHello->random.random_bytes));
			pcCurSslData += sizeof(a_ssl_stream->stClientHello->random.random_bytes);
			iUnAnaHelloLen -= sizeof(a_ssl_stream->stClientHello->random.random_bytes);
			if (iUnAnaHelloLen < 0)
			{
				return SSL_RETURN_DROPME;
			}

			/*get client hello session*/
			a_ssl_stream->stClientHello->session.session_len = (unsigned char)BtoL1BytesNum(pcCurSslData);
			pcCurSslData += sizeof(a_ssl_stream->stClientHello->session.session_len);
			iUnAnaHelloLen -= sizeof(a_ssl_stream->stClientHello->session.session_len);
			if (iUnAnaHelloLen < 0)
			{
				return SSL_RETURN_DROPME;
			}
			if (a_ssl_stream->stClientHello->session.session_len > iUnAnaHelloLen)
			{
				return SSL_RETURN_DROPME;
			}
			if (a_ssl_stream->stClientHello->session.session_len != 0)
			{
				a_ssl_stream->stClientHello->session.session_value = (unsigned char *)dictator_malloc(thread_seq, a_ssl_stream->stClientHello->session.session_len);
				memcpy(a_ssl_stream->stClientHello->session.session_value, pcCurSslData, a_ssl_stream->stClientHello->session.session_len);
				pcCurSslData += a_ssl_stream->stClientHello->session.session_len;
				iUnAnaHelloLen -= a_ssl_stream->stClientHello->session.session_len;
				if (iUnAnaHelloLen < 0)
				{
					return SSL_RETURN_DROPME;
				}
			}

			/*get client hello suites*/
			a_ssl_stream->stClientHello->ciphersuites.suites_len = (unsigned short)BtoL2BytesNum(pcCurSslData);
			pcCurSslData += sizeof(a_ssl_stream->stClientHello->ciphersuites.suites_len);
			iUnAnaHelloLen -= sizeof(a_ssl_stream->stClientHello->ciphersuites.suites_len);
			if (iUnAnaHelloLen < 0)
			{
				return SSL_RETURN_DROPME;
			}
			if (a_ssl_stream->stClientHello->ciphersuites.suites_len > iUnAnaHelloLen)
			{
				return SSL_RETURN_DROPME;
			}
			if (a_ssl_stream->stClientHello->ciphersuites.suites_len != 0)
			{
				a_ssl_stream->stClientHello->ciphersuites.suites_value = (unsigned char *)dictator_malloc(thread_seq, a_ssl_stream->stClientHello->ciphersuites.suites_len);
				memcpy(a_ssl_stream->stClientHello->ciphersuites.suites_value, pcCurSslData, a_ssl_stream->stClientHello->ciphersuites.suites_len);
				pcCurSslData += a_ssl_stream->stClientHello->ciphersuites.suites_len;
				iUnAnaHelloLen -= a_ssl_stream->stClientHello->ciphersuites.suites_len;
				if (iUnAnaHelloLen < 0)
				{
					return SSL_RETURN_DROPME;
				}
			}

			/*get client hello compress*/
			a_ssl_stream->stClientHello->com_method.methlen = (unsigned short)BtoL1BytesNum(pcCurSslData);
			pcCurSslData += sizeof(a_ssl_stream->stClientHello->com_method.methlen);
			iUnAnaHelloLen -= sizeof(a_ssl_stream->stClientHello->com_method.methlen);
			if (iUnAnaHelloLen < 0)
			{
				return SSL_RETURN_DROPME;
			}
			if (a_ssl_stream->stClientHello->com_method.methlen > iUnAnaHelloLen)
			{
				return SSL_RETURN_DROPME;
			}
			if (a_ssl_stream->stClientHello->com_method.methlen != 0)
			{
				a_ssl_stream->stClientHello->com_method.methods = (unsigned char *)dictator_malloc(thread_seq, a_ssl_stream->stClientHello->com_method.methlen);
				memcpy(a_ssl_stream->stClientHello->com_method.methods, pcCurSslData, a_ssl_stream->stClientHello->com_method.methlen);
				pcCurSslData += a_ssl_stream->stClientHello->com_method.methlen;
				iUnAnaHelloLen -= a_ssl_stream->stClientHello->com_method.methlen;
				if (iUnAnaHelloLen < 0)
				{
					return SSL_RETURN_DROPME;
				}
			}

			/*get extension*/
			st_ext_t exts_on_stack[64];
			memset(&exts_on_stack, 0, sizeof(exts_on_stack));
			a_ssl_stream->stClientHello->extlen = (unsigned short)BtoL2BytesNum(pcCurSslData);
			pcCurSslData += sizeof(a_ssl_stream->stClientHello->extlen);

			int i = 0;
			for (i = 0; iUnAnaHelloLen >= 4 && i < 64; i++) // min len of ext is 4 byte
			{

				exts_on_stack[i].type = (unsigned short)BtoL2BytesNum(pcCurSslData);
				pcCurSslData += sizeof(exts_on_stack[i].type);
				iUnAnaHelloLen -= sizeof(exts_on_stack[i].type);
				if (iUnAnaHelloLen < 0)
				{
					return SSL_RETURN_DROPME;
				}

				exts_on_stack[i].len = (unsigned short)BtoL2BytesNum(pcCurSslData);
				pcCurSslData += sizeof(exts_on_stack[i].len);
				iUnAnaHelloLen -= sizeof(exts_on_stack[i].len);
				if (iUnAnaHelloLen < 0 || exts_on_stack[i].len > iUnAnaHelloLen)
				{
					return SSL_RETURN_DROPME;
				}
				exts_on_stack[i].data=(unsigned char *)pcCurSslData;


				pcCurSslData += exts_on_stack[i].len;
				iUnAnaHelloLen -= exts_on_stack[i].len;
			}
			int ext_on_stack_num = i;
			// printf("ext_num: %d\n", a_ssl_stream->stClientHello->ext_num);
			return_val = ssl_doWithClientHello(exts_on_stack, ext_on_stack_num, &a_ssl_stream, a_tcp, region_flag, thread_seq, a_packet);
			a_ssl_stream->stClientHello->ext_num = 0;
			a_ssl_stream->stClientHello->session_ticket.ticket = NULL;
			if (a_ssl_stream->stClientHello->session.session_value != NULL)
			{
				dictator_free(thread_seq, a_ssl_stream->stClientHello->session.session_value);
				a_ssl_stream->stClientHello->session.session_value = NULL;
			}
			if (a_ssl_stream->stClientHello->ciphersuites.suites_value != NULL)
			{
				dictator_free(thread_seq, a_ssl_stream->stClientHello->ciphersuites.suites_value);
				a_ssl_stream->stClientHello->ciphersuites.suites_value = NULL;
			}
			if (a_ssl_stream->stClientHello->com_method.methods != NULL)
			{
				dictator_free(thread_seq, a_ssl_stream->stClientHello->com_method.methods);
				a_ssl_stream->stClientHello->com_method.methods = NULL;
			}

			if (SSL_RETURN_NORM != return_val)
				return return_val;
			iUnAnalyseLen -= (a_ssl_stream->stClientHello->totallen + CLIENT_HELLO_HDRLEN);
			pcSslData += (a_ssl_stream->stClientHello->totallen + CLIENT_HELLO_HDRLEN);
		}

		/**analyse server_hello**/
		else if (SERVER_HELLO == pstHandShakeTypeHdr->ucContType)
		{
			if (iUnAnalyseLen < SERVER_HELLO_HDRLEN)
			{
				break;
			}
			if (a_ssl_stream->stServerHello == NULL)
			{
				a_ssl_stream->stServerHello = (st_server_hello_t *)dictator_malloc(thread_seq, sizeof(st_server_hello_t));
				memset(a_ssl_stream->stServerHello, 0, sizeof(st_server_hello_t));
				ssl_initStructServerHello(a_ssl_stream->stServerHello);
			}
			a_ssl_stream->stServerHello->totallen = BtoL3BytesNum((char *)(pcCurSslData + 1));
			if (a_ssl_stream->stServerHello->totallen < 0)
				return SSL_RETURN_DROPME;

			/*4 means client_type+len*/
			if (a_ssl_stream->stServerHello->totallen + SERVER_HELLO_HDRLEN > iUnAnalyseLen)
			{
				/**packet trunked**/
				break;
			}
			if (0 == (a_ssl_stream->stServerHello->server_ver = ssl_getHelloVersion((unsigned char *)pcCurSslData, iUnAnalyseLen)))
			{
				return SSL_RETURN_DROPME;
			}

			iUnAnaHelloLen = a_ssl_stream->stServerHello->totallen - sizeof(a_ssl_stream->stServerHello->server_ver);
			if (iUnAnaHelloLen < 0)
			{
				return SSL_RETURN_DROPME;
			}

			pcCurSslData += SERVER_HELLO_HDRLEN + sizeof(a_ssl_stream->stServerHello->server_ver);

			/*get server hello random*/
			a_ssl_stream->stServerHello->random.gmt_time = (unsigned int)BtoL4BytesNum(pcCurSslData);
			pcCurSslData += sizeof(a_ssl_stream->stServerHello->random.gmt_time);
			iUnAnaHelloLen -= sizeof(a_ssl_stream->stServerHello->random.gmt_time);
			if (iUnAnaHelloLen < 0)
			{
				return SSL_RETURN_DROPME;
			}
			memcpy(a_ssl_stream->stServerHello->random.random_bytes, pcCurSslData, sizeof(a_ssl_stream->stServerHello->random.random_bytes));
			pcCurSslData += sizeof(a_ssl_stream->stServerHello->random.random_bytes);
			iUnAnaHelloLen -= sizeof(a_ssl_stream->stServerHello->random.random_bytes);
			if (iUnAnaHelloLen < 0)
			{
				return SSL_RETURN_DROPME;
			}

			/*get server hello session*/
			a_ssl_stream->stServerHello->session.session_len = (unsigned char)BtoL1BytesNum(pcCurSslData);
			pcCurSslData += sizeof(a_ssl_stream->stServerHello->session.session_len);
			iUnAnaHelloLen -= sizeof(a_ssl_stream->stServerHello->session.session_len);
			if (iUnAnaHelloLen < 0)
			{
				return SSL_RETURN_DROPME;
			}
			if (a_ssl_stream->stServerHello->session.session_len > iUnAnaHelloLen)
			{
				return SSL_RETURN_DROPME;
			}
			if (a_ssl_stream->stServerHello->session.session_len != 0)
			{
				a_ssl_stream->stServerHello->session.session_value = (unsigned char *)dictator_malloc(thread_seq, a_ssl_stream->stServerHello->session.session_len);
				memcpy(a_ssl_stream->stServerHello->session.session_value, pcCurSslData, a_ssl_stream->stServerHello->session.session_len);
				pcCurSslData += a_ssl_stream->stServerHello->session.session_len;
				iUnAnaHelloLen -= a_ssl_stream->stServerHello->session.session_len;
				if (iUnAnaHelloLen < 0)
				{
					return SSL_RETURN_DROPME;
				}
			}

			/*get server hello suites*/
			a_ssl_stream->stServerHello->ciphersuites.suites_len = 2;
			a_ssl_stream->stServerHello->ciphersuites.suites_value = (unsigned char *)dictator_malloc(thread_seq, a_ssl_stream->stServerHello->ciphersuites.suites_len);
			memcpy(a_ssl_stream->stServerHello->ciphersuites.suites_value, pcCurSslData, a_ssl_stream->stServerHello->ciphersuites.suites_len);
			pcCurSslData += a_ssl_stream->stServerHello->ciphersuites.suites_len;
			iUnAnaHelloLen -= a_ssl_stream->stServerHello->ciphersuites.suites_len;
			if (iUnAnaHelloLen < 0)
			{
				return SSL_RETURN_DROPME;
			}

			/*get server hello compress*/
			/*
			a_ssl_stream->stServerHello->com_method.methlen = (unsigned short)BtoL1BytesNum(pcCurSslData);
			pcCurSslData += sizeof(a_ssl_stream->stServerHello->com_method.methlen);
			iUnAnaHelloLen -= sizeof(a_ssl_stream->stServerHello->com_method.methlen);
			if(iUnAnaHelloLen<0)
			{
				return SSL_RETURN_DROPME;
			}
			*/
			/*20160906 methlenֻռһ���ֽ�*/
			a_ssl_stream->stServerHello->com_method.methlen = 1;
			a_ssl_stream->stServerHello->com_method.methods = (unsigned char *)dictator_malloc(thread_seq, a_ssl_stream->stServerHello->com_method.methlen);
			memcpy(a_ssl_stream->stServerHello->com_method.methods, pcCurSslData, a_ssl_stream->stServerHello->com_method.methlen);
			pcCurSslData += a_ssl_stream->stServerHello->com_method.methlen;
			iUnAnaHelloLen -= a_ssl_stream->stServerHello->com_method.methlen;
			if (iUnAnaHelloLen < 0)
			{
				return SSL_RETURN_DROPME;
			}
			

			/*get extension*/
			a_ssl_stream->stServerHello->extlen = (unsigned short)BtoL2BytesNum(pcCurSslData);
			pcCurSslData += sizeof(a_ssl_stream->stServerHello->extlen);

			int i = 0;
			for (i = 0; iUnAnaHelloLen >= 4 && i < MAX_EXTENSION_NUM; i++) // min len of ext is 4 byte
			{
				a_ssl_stream->stServerHello->exts[i].type = (unsigned short)BtoL2BytesNum(pcCurSslData);
				pcCurSslData += sizeof(a_ssl_stream->stServerHello->exts[i].type);
				iUnAnaHelloLen -= sizeof(a_ssl_stream->stServerHello->exts[i].type);
				if (iUnAnaHelloLen < 0)
				{
					return SSL_RETURN_DROPME;
				}

				a_ssl_stream->stServerHello->exts[i].len = (unsigned short)BtoL2BytesNum(pcCurSslData);
				pcCurSslData += sizeof(a_ssl_stream->stServerHello->exts[i].len);
				iUnAnaHelloLen -= sizeof(a_ssl_stream->stServerHello->exts[i].len);
				if (iUnAnaHelloLen < 0 || a_ssl_stream->stServerHello->exts[i].len > iUnAnaHelloLen)
				{
					return SSL_RETURN_DROPME;
				}
				a_ssl_stream->stServerHello->exts[i].data = (unsigned char *)dictator_malloc(thread_seq, a_ssl_stream->stServerHello->exts[i].len);
				memcpy(a_ssl_stream->stServerHello->exts[i].data, pcCurSslData, a_ssl_stream->stServerHello->exts[i].len); // get ext data
				pcCurSslData += a_ssl_stream->stServerHello->exts[i].len;
				iUnAnaHelloLen -= a_ssl_stream->stServerHello->exts[i].len;
			}
			a_ssl_stream->stServerHello->ext_num = i;

			for (int j = 0; j < a_ssl_stream->stServerHello->ext_num; j++)
			{
				if (a_ssl_stream->stServerHello->exts[j].data != NULL)
				{
					dictator_free(thread_seq, a_ssl_stream->stServerHello->exts[j].data);
					a_ssl_stream->stServerHello->exts[j].data = NULL;
				}
			}
			a_ssl_stream->stServerHello->ext_num = 0;

			return_val = ssl_doWithServerHello(&a_ssl_stream, a_tcp, region_flag, thread_seq, a_packet);
			// 20141121
			if (a_ssl_stream->stServerHello->session.session_value != NULL)
			{
				dictator_free(thread_seq, a_ssl_stream->stServerHello->session.session_value);
				a_ssl_stream->stServerHello->session.session_value = NULL;
			}
			if (a_ssl_stream->stServerHello->ciphersuites.suites_value != NULL)
			{
				dictator_free(thread_seq, a_ssl_stream->stServerHello->ciphersuites.suites_value);
				a_ssl_stream->stServerHello->ciphersuites.suites_value = NULL;
			}
			if (a_ssl_stream->stServerHello->com_method.methods != NULL)
			{
				dictator_free(thread_seq, a_ssl_stream->stServerHello->com_method.methods);
				a_ssl_stream->stServerHello->com_method.methods = NULL;
			}
			if (SSL_RETURN_NORM != return_val)
				return return_val;
			iUnAnalyseLen -= (a_ssl_stream->stServerHello->totallen + SERVER_HELLO_HDRLEN);
			pcSslData += (a_ssl_stream->stServerHello->totallen + SERVER_HELLO_HDRLEN);
		}
		else if (NEW_SESSION_TICKET == pstHandShakeTypeHdr->ucContType)
		{
			if (iUnAnalyseLen < SESSION_TICKET_HDRLEN)
			{
				break;
			}
			if (a_ssl_stream->stNewSessionTicket == NULL)
			{
				a_ssl_stream->stNewSessionTicket = (st_new_session_ticket_t *)dictator_malloc(thread_seq, sizeof(st_new_session_ticket_t));
				memset(a_ssl_stream->stNewSessionTicket, 0, sizeof(st_new_session_ticket_t));
			}
			a_ssl_stream->stNewSessionTicket->totallen = BtoL3BytesNum((char *)(pcCurSslData + 1));
			if (a_ssl_stream->stNewSessionTicket->totallen < 0)
				return SSL_RETURN_DROPME;

			/*4 means _type+len*/
			if (a_ssl_stream->stNewSessionTicket->totallen + SESSION_TICKET_HDRLEN > iUnAnalyseLen)
			{
				/**packet trunked**/
				break;
			}
			pcCurSslData += SESSION_TICKET_HDRLEN;
			a_ssl_stream->stNewSessionTicket->lifttime = BtoL4BytesNum((char *)(pcCurSslData));
			a_ssl_stream->stNewSessionTicket->ticket_len = BtoL2BytesNum((char *)(pcCurSslData + 4));
			a_ssl_stream->stNewSessionTicket->ticket = (unsigned char *)(pcCurSslData + 6);
			pcCurSslData += 6 + a_ssl_stream->stNewSessionTicket->ticket_len;
			iUnAnalyseLen -= (a_ssl_stream->stNewSessionTicket->totallen + SERVER_HELLO_HDRLEN);
			pcSslData += (a_ssl_stream->stNewSessionTicket->totallen + SERVER_HELLO_HDRLEN);
			ssl_doWithNewSessionTicket(&a_ssl_stream, a_tcp, region_flag, thread_seq, a_packet);
			// printf("new session ticket:%d\n", a_ssl_stream->stNewSessionTicket->ticket_len);
		}
		else
		{
			break;
		}
	}

	*res = (iSslDataLen - iUnAnalyseLen);
	return SSL_RETURN_NORM;
}

UCHAR ssl_analyseAppData(char *pcSslData, int iAllMsgLen, int iSslUnAnalyseLen, int *res, ssl_stream *a_ssl_stream, struct streaminfo *a_tcp,
						 unsigned long long region_flag, int thread_seq, void *a_packet)
{
	/**variable define and initialise**/
	int return_val = SSL_RETURN_NORM;
	int iUnAnalyseLen = iAllMsgLen < iSslUnAnalyseLen ? iAllMsgLen : iSslUnAnalyseLen;

	/**validaty check**/
	if (NULL == pcSslData || iUnAnalyseLen <= 0)
	{
		*res = 0;
		return SSL_RETURN_NORM;
	}
	a_ssl_stream->output_region_mask = SSL_APPLICATION_DATA_MASK;
	a_ssl_stream->p_output_buffer->p_data = pcSslData;
	a_ssl_stream->p_output_buffer->data_size = iUnAnalyseLen;
	return_val = ssl_doWithApplicationData(&a_ssl_stream, a_tcp, region_flag, thread_seq, a_packet);
	a_ssl_stream->p_output_buffer->p_data = NULL;
	a_ssl_stream->p_output_buffer->data_size = 0;
	*res = iUnAnalyseLen;
	if (SSL_RETURN_NORM != return_val)
		return return_val;
	return SSL_RETURN_NORM;
}

UCHAR ssl_analyseAlert(char *pcSslData, int iAllMsgLen, int iSslUnAnalyseLen, int *res, ssl_stream *a_ssl_stream, struct streaminfo *a_tcp,
					   unsigned long long region_flag, int thread_seq, void *a_packet)
{
	/**variable define and initialise**/
	int return_val = SSL_RETURN_NORM;
	int iUnAnalyseLen = iAllMsgLen < iSslUnAnalyseLen ? iAllMsgLen : iSslUnAnalyseLen;

	/**validaty check**/
	if (NULL == pcSslData || iUnAnalyseLen <= 0)
	{
		*res = 0;
		return SSL_RETURN_NORM;
	}
	a_ssl_stream->output_region_mask = SSL_ALERT_MASK;
	a_ssl_stream->p_output_buffer->p_data = pcSslData;
	a_ssl_stream->p_output_buffer->data_size = iUnAnalyseLen;
	return_val = ssl_doWithAlert(&a_ssl_stream, a_tcp, region_flag, thread_seq, a_packet);
	a_ssl_stream->p_output_buffer->p_data = NULL;
	a_ssl_stream->p_output_buffer->data_size = 0;
	*res = iUnAnalyseLen;
	if (SSL_RETURN_NORM != return_val)
		return return_val;
	return SSL_RETURN_NORM;
}

char *fn_pcGetType(const unsigned char *pucId, int iIdLen, stSerialString_t *pastElemTypes)
{
	int iLoop;
	int iInLoop;

	if (NULL == pucId || iIdLen < 0 || NULL == pastElemTypes)
	{
		return NULL;
	}

	for (iLoop = 0; NULL != pastElemTypes[iLoop].pcString; ++iLoop)
	{
		for (iInLoop = 0; iInLoop < iIdLen; ++iInLoop)
		{
			if (pucId[iInLoop] != pastElemTypes[iLoop].aucSerial[iInLoop])
			{
				break;
			}
		}
		if (iInLoop == iIdLen)
		{
			return (char *)(pastElemTypes[iLoop].pcString);
		}
	}

	return NULL;
}

int ssl_protoRecg(char *pcData, int iDataLen)
{
	if (NULL == pcData || iDataLen < 1)
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

#define MAX_THREAD_NUM 64
#define COUNTER_NUM 4096

extern volatile unsigned long long g_SysInputInfo[MAX_THREAD_NUM][COUNTER_NUM];

UCHAR ssl_analyseSsl(char *pcSslData, int iDataLen, int *res, ssl_stream *a_ssl_stream, struct streaminfo *a_tcp,
					 unsigned long long region_flag, int thread_seq, void *a_packet)
{
	/**variable define and initialise**/
	stSSLRecordHdr_t *pstSSLRecordHdr = NULL;
	stHandShakeTypeHdr_t *pstHandShakeTypeHdr = NULL;
	int iUnAnalyseLen = iDataLen;
	char *pcCurSslData = pcSslData;
	int iCurAllMsgLen = 0;
	int iCurMsgLen = 0;
	int is_trunk = 0;
	UCHAR return_val = SSL_RETURN_NORM;

	/**validaty check**/
	if (NULL == pcSslData || iDataLen < SSL_HEADER_LEN)
	{
		*res = 0;
		return SSL_RETURN_NORM;
	}

	/**first packet of an hand shake conversation**/
	if (UNKNOWN_VERSION == a_ssl_stream->uiSslVersion)
	{
		a_ssl_stream->uiSslVersion = (unsigned int)ssl_protoRecg(pcSslData, iDataLen);
		/*jump the first pkt*/
		if (UNKNOWN_VERSION == a_ssl_stream->uiSslVersion)
		{
			*res = -1;
			if (a_ssl_stream->first_pkt_flag == 0)
			{
				a_ssl_stream->first_pkt_flag = 1;
				return SSL_RETURN_GIVEME;
			}
			else
			{
				return SSL_RETURN_DROPME;
			}
		}
		/*version callback*/
		return_val = ssl_doWithVersion(&a_ssl_stream, a_tcp, region_flag, thread_seq, a_packet);
		if (SSL_RETURN_NORM != return_val)
			return return_val;
	}
	// 2020.11.27  iUnAnalyseLen need more than SSL_RECORD_HDRLEN
	while (iUnAnalyseLen > SSL_RECORD_HDRLEN)
	{
		if (SSL_HANDSHAKE_MSG_TRUNKED == a_ssl_stream->uiMsgState)
		{
			switch (a_ssl_stream->ucContType)
			{
			case HANDSHAKE:
			case APPLICATION_DATA:
			case ALERT:
				pstHandShakeTypeHdr = (stHandShakeTypeHdr_t *)pcCurSslData;
				iCurAllMsgLen = (a_ssl_stream->uiAllMsgLen - a_ssl_stream->uiMsgProcLen);
				iCurMsgLen = (a_ssl_stream->uiAllMsgLen - a_ssl_stream->uiMsgProcLen) < iUnAnalyseLen ? (a_ssl_stream->uiAllMsgLen - a_ssl_stream->uiMsgProcLen) : iUnAnalyseLen;
				a_ssl_stream->uiMsgState = SSL_HANDSHAKE_NOTRUNK;
				break;
			default:
				a_ssl_stream->uiMsgState = SSL_HANDSHAKE_NOTRUNK;
				a_ssl_stream->ucContType = 0;
				*res = -1;
				return SSL_RETURN_NORM;
			}
		}
		else
		{

			pstSSLRecordHdr = (stSSLRecordHdr_t *)pcCurSslData;
			switch (pstSSLRecordHdr->ucContType)
			{
			case HANDSHAKE:
				a_ssl_stream->ucContType = HANDSHAKE;
				a_ssl_stream->is_ssl_stream = SSL_TRUE;
				a_ssl_stream->uiAllMsgLen = htons(pstSSLRecordHdr->usTotalLen);
				pstHandShakeTypeHdr = (stHandShakeTypeHdr_t *)(pcCurSslData + SSL_RECORD_HDRLEN);
				pcCurSslData += SSL_RECORD_HDRLEN;
				iUnAnalyseLen -= SSL_RECORD_HDRLEN;
				iCurAllMsgLen = a_ssl_stream->uiAllMsgLen;
				iCurMsgLen = a_ssl_stream->uiAllMsgLen < iUnAnalyseLen ? a_ssl_stream->uiAllMsgLen : iUnAnalyseLen;
				a_ssl_stream->uiMsgState = SSL_HANDSHAKE_NOTRUNK;
				break;

			case APPLICATION_DATA:
				a_ssl_stream->ucContType = APPLICATION_DATA;
				a_ssl_stream->is_ssl_stream = SSL_TRUE;
				a_ssl_stream->uiAllMsgLen = htons(pstSSLRecordHdr->usTotalLen);
				pcCurSslData += SSL_RECORD_HDRLEN;
				iUnAnalyseLen -= SSL_RECORD_HDRLEN;
				iCurAllMsgLen = a_ssl_stream->uiAllMsgLen;
				iCurMsgLen = a_ssl_stream->uiAllMsgLen < iUnAnalyseLen ? a_ssl_stream->uiAllMsgLen : iUnAnalyseLen;
				a_ssl_stream->uiMsgState = SSL_HANDSHAKE_NOTRUNK;
				// static int count;
				// count++;
				// printf("%d\t%d\t%lld\n",count, a_ssl_stream->uiAllMsgLen, g_SysInputInfo[0][0]);
				break;

			case CHANGE_CIPHER_SEP:
				a_ssl_stream->ucContType = CHANGE_CIPHER_SEP;
				a_ssl_stream->is_ssl_stream = SSL_TRUE;
				a_ssl_stream->uiAllMsgLen = htons(pstSSLRecordHdr->usTotalLen);
				iCurAllMsgLen = a_ssl_stream->uiAllMsgLen;
				pcCurSslData += SSL_RECORD_HDRLEN;
				iUnAnalyseLen -= SSL_RECORD_HDRLEN;
				iCurMsgLen = a_ssl_stream->uiAllMsgLen < iUnAnalyseLen ? a_ssl_stream->uiAllMsgLen : iUnAnalyseLen;
				a_ssl_stream->uiMsgState = SSL_HANDSHAKE_NOTRUNK;
				*res = iCurAllMsgLen;
				break;

			case ALERT:
				a_ssl_stream->ucContType = ALERT;
				a_ssl_stream->is_ssl_stream = SSL_TRUE;
				a_ssl_stream->uiAllMsgLen = htons(pstSSLRecordHdr->usTotalLen);
				iCurAllMsgLen = a_ssl_stream->uiAllMsgLen;
				pcCurSslData += SSL_RECORD_HDRLEN;
				iUnAnalyseLen -= SSL_RECORD_HDRLEN;
				iCurMsgLen = a_ssl_stream->uiAllMsgLen < iUnAnalyseLen ? a_ssl_stream->uiAllMsgLen : iUnAnalyseLen;
				a_ssl_stream->uiMsgState = SSL_HANDSHAKE_NOTRUNK;
				*res = iCurAllMsgLen;
				break;

			default:
				if (a_ssl_stream->is_ssl_stream == SSL_TRUE)
				{
					a_ssl_stream->uiMsgState = SSL_HANDSHAKE_NOTRUNK;
					a_ssl_stream->ucContType = 0;
					*res = -1;
					return SSL_RETURN_NORM;
				}
				else
				{
					a_ssl_stream->uiMsgState = SSL_HANDSHAKE_NOTRUNK;
					a_ssl_stream->ucContType = 0;
					*res = -1;
					return SSL_RETURN_DROPME;
				}
			}
		}
		switch (a_ssl_stream->ucContType)
		{
			case APPLICATION_DATA:
				/*���������ݣ�ʵʱ����*/
				return_val = ssl_analyseAppData((char *)pcCurSslData, iCurAllMsgLen, iUnAnalyseLen, res, a_ssl_stream, a_tcp, region_flag, thread_seq, a_packet);
				/*the data is not enough*/
				if (*res < iCurAllMsgLen)
				{
					is_trunk = 1;
				}
				break;

			/*��������ȫ������ٴ���*/
			case ALERT:
				// printf("%d:%d\n",iCurAllMsgLen,iUnAnalyseLen);
				if (iUnAnalyseLen < iCurAllMsgLen)
				{
					*res = 0;
					is_trunk = 1;
				}
				else
				{
					return_val = ssl_analyseAlert((char *)pcCurSslData, iCurAllMsgLen, iUnAnalyseLen, res, a_ssl_stream, a_tcp, region_flag, thread_seq, a_packet);
					is_trunk = 0;
				}
				break;

			/*other handshark proto not process*/
			case HANDSHAKE:
				/*���幻�����ٴ���*/
				if (fn_iIsHandShakeMsg(*(unsigned char *)pstHandShakeTypeHdr))
				{
					/*res��ʾ����������*/
					return_val = ssl_analyseHandShake((char *)pstHandShakeTypeHdr, iCurAllMsgLen, iUnAnalyseLen, res, a_ssl_stream, a_tcp, region_flag, thread_seq, a_packet);
					if (*res < iCurAllMsgLen)
					{
						is_trunk = 1;
					}
				}
				else
				{
					if (iCurMsgLen >= iCurAllMsgLen)
					{
						/*����Ϣ�������*/
						*res = iCurMsgLen;
					}
					else
					{
						/*��ʾ��Ҫ���浱ǰ���ݰ����������ݣ�����*res������������Ϊ0*/
						*res = 0;
						is_trunk = 1;
					}
				}
				/*20140731 res<0 but no why*/
				if (*res < 0)
				{
					return SSL_RETURN_DROPME;
				}
				break;

			default:
				*res = iCurMsgLen;
				break;
		}

		/*the data is not enough*/
		if (is_trunk)
		// if(*res < iCurMsgLen)
		{
			a_ssl_stream->uiMsgState = SSL_HANDSHAKE_MSG_TRUNKED;
			a_ssl_stream->uiMsgProcLen += *res;
			//pcCurSslData += *res;  //20220318 cppcheck
			iUnAnalyseLen -= *res;
			break;
		}
		else
		{
			/*������Ϣ�������*/
			a_ssl_stream->uiAllMsgLen = 0;
			a_ssl_stream->uiMsgProcLen = 0;
		}

		if (SSL_RETURN_NORM != return_val)
		{
			return return_val;
		}

		pcCurSslData += *res;
		iUnAnalyseLen -= *res;
	}

	*res = iDataLen - iUnAnalyseLen;

	return SSL_RETURN_NORM;
}

#include "field_stat2.h"

struct ssl_frag_chello *ssl_frag_chello_get0(struct streaminfo *a_tcp)
{
	if(g_ssl_prog_para.detain_frag_chello_num == 0 || a_tcp->curdir != DIR_C2S || a_tcp->dir != DIR_DOUBLE)return NULL;
    struct frag_chello_internal *pkts = (struct frag_chello_internal *)stream_bridge_async_data_get(a_tcp, g_ssl_prog_para.frag_chello_exdata_idx);	
	if(pkts)
	{
		return &pkts->frag_chello;
	}
	return NULL;
}

static void ssl_detain_frag_chello(const struct streaminfo *a_tcp)
{
	if(g_ssl_prog_para.detain_frag_chello_num == 0 || a_tcp->curdir != DIR_C2S || a_tcp->dir != DIR_DOUBLE)return;
	
    struct frag_chello_internal *pkts = (struct frag_chello_internal *)stream_bridge_async_data_get(a_tcp, g_ssl_prog_para.frag_chello_exdata_idx);
    if (pkts == NULL)
    {
        pkts=(struct frag_chello_internal *)calloc(sizeof(struct frag_chello_internal), 1);
		if(g_ssl_prog_para.stat_handler)
		{
			FS_operate(g_ssl_prog_para.stat_handler, g_ssl_prog_para.stat_field[FS_METRIC_DETAIN_FRAG_CHELLO_SESSION], 0, FS_OP_ADD, 1);
		}
    }
	if(pkts->finish == 1)return;
	const void *p = get_current_rawpkt_from_streaminfo(a_tcp);
	struct detain_pkt *dpkt=MESA_rawpkt_detain(a_tcp, p);
	if(dpkt && pkts->frag_chello.p_sz<g_ssl_prog_para.detain_frag_chello_num)
	{
		pkts->frag_chello.p[pkts->frag_chello.p_sz]=dpkt;
		pkts->frag_chello.p_sz+=1;
		if(pkts->frag_chello.p_sz==g_ssl_prog_para.detain_frag_chello_num)pkts->finish=1;
		if(g_ssl_prog_para.stat_handler)
		{
			FS_operate(g_ssl_prog_para.stat_handler, g_ssl_prog_para.stat_field[FS_METRIC_DETAIN_FRAG_CHELLO_NUM], 0, FS_OP_ADD, 1);	
		}
	}
    stream_bridge_async_data_put(a_tcp, g_ssl_prog_para.frag_chello_exdata_idx, pkts);
	return;
}

static void ssl_detain_chello_finish(const struct streaminfo *a_tcp)
{
	if(g_ssl_prog_para.detain_frag_chello_num == 0)return;
	struct frag_chello_internal *pkts = (struct frag_chello_internal *)stream_bridge_async_data_get(a_tcp, g_ssl_prog_para.frag_chello_exdata_idx);
	if(pkts)pkts->finish=1;
	if(g_ssl_prog_para.stat_handler)
	{	
		FS_operate(g_ssl_prog_para.stat_handler, g_ssl_prog_para.stat_field[FS_METRIC_DETAIN_FRAG_CHELLO_FINISH], 0, FS_OP_ADD, 1);	
	}
	return;
}


UCHAR ssl_analyseStream(struct streaminfo *a_tcp, void **pme, int thread_seq, void *a_packet)
{
	/**variables define, and initialise**/
	int return_val = APP_STATE_GIVEME;
	ssl_stream *a_ssl_stream = (ssl_stream *)*pme;
	struct tcpdetail *tcp_detail = (struct tcpdetail *)a_tcp->pdetail;
	char *pcSslData = NULL;
	int iSslDateLen = 0;
	int iRet = 0;

	if (NULL == a_ssl_stream)
	{
		return SSL_RETURN_DROPME;
	}

	if (0 == tcp_detail->datalen)
	{
		/*trans ssl over state*/
		if (a_ssl_stream->over_flag == SSL_TRUE && a_ssl_stream->uiSslVersion != UNKNOWN_VERSION)
		{
			return ssl_callPlugins(&a_ssl_stream, a_tcp, a_ssl_stream->output_region_flag, thread_seq, a_packet);
		}
		else
			return APP_STATE_GIVEME;
	}

	/**if buffered, copy new data to the buff**/
	/**if lose packets, drop the buffered data**/
	/*bad data fill the buffer,  or lose pkt clear it*/
	if ((tcp_detail->lostlen > 0) || (a_ssl_stream->uiMaxBuffLen > 0 && a_ssl_stream->uiCurBuffLen >= a_ssl_stream->uiMaxBuffLen))
	{
		// 20151231
		return SSL_RETURN_DROPME;
		a_ssl_stream->uiCurBuffLen = 0;
	}

	if (a_ssl_stream->uiCurBuffLen > 0)
	{
		// 20151231 not enough,tcp_detail->pdata will be cut, it's not useful
		if (a_ssl_stream->uiMaxBuffLen - a_ssl_stream->uiCurBuffLen < (int)tcp_detail->datalen)
		{
			return SSL_RETURN_DROPME;
		}
		iSslDateLen = MIN((int)tcp_detail->datalen, (a_ssl_stream->uiMaxBuffLen - a_ssl_stream->uiCurBuffLen));

		memcpy(a_ssl_stream->pcSslBuffer + a_ssl_stream->uiCurBuffLen, tcp_detail->pdata, iSslDateLen);
		a_ssl_stream->uiCurBuffLen += iSslDateLen;
		iSslDateLen = a_ssl_stream->uiCurBuffLen;
		pcSslData = a_ssl_stream->pcSslBuffer;
		ssl_detain_frag_chello(a_tcp);
	}
	else
	{
		pcSslData = (char *)tcp_detail->pdata;
		iSslDateLen = tcp_detail->datalen;
	}

	return_val = ssl_analyseSsl(pcSslData, iSslDateLen, &iRet, a_ssl_stream, a_tcp, a_ssl_stream->output_region_flag, thread_seq, a_packet);

	if (SSL_RETURN_NORM != return_val)
	{
		return return_val;
	}
	/*is ssl_stream, need buffer data*/
	if (iRet < 0 || iRet >= iSslDateLen)
	{
		ssl_detain_chello_finish(a_tcp);
		a_ssl_stream->uiCurBuffLen = 0;
	}
	else
	{
		if (0 == a_ssl_stream->uiMaxBuffLen)
		{
			a_ssl_stream->pcSslBuffer = (char *)dictator_malloc(thread_seq, MAX_DATA_BUFFER);
			memset(a_ssl_stream->pcSslBuffer, 0, MAX_DATA_BUFFER);
			a_ssl_stream->uiMaxBuffLen = MAX_DATA_BUFFER;
		}
		fn_vMemCpy(a_ssl_stream->pcSslBuffer, (int)a_ssl_stream->uiMaxBuffLen, pcSslData + iRet, (int)(iSslDateLen - iRet));
		a_ssl_stream->uiCurBuffLen = iSslDateLen - iRet;
		ssl_detain_frag_chello(a_tcp);
	}
	return return_val;
}
