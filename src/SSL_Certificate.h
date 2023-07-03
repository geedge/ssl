#pragma once

#define	CERT_TYPE_MAXNUM			16
//#define SCT_OID 					1.3.6.1.4.1.11129.2.4.2
#define SCT_OID 					1

int x509_parse_certificate_detail(struct ssl_certificate *certificate, char *cert_payload, int cert_payload_len, int thread_seq);
