#pragma once

int BtoL1BytesNum(const char *pcData);
int BtoL2BytesNum(const char *pcData);
int BtoL3BytesNum(const char *pcData);
int BtoL4BytesNum(const char *pcData);

int ssl_identify_version(char *pcData, int iDataLen);
char *fn_pcGetSuite(unsigned char *pucId, int iIdLen, struct ssl_serial_string *pastElemTypes);
void ssl_call_plugins(const struct streaminfo *a_tcp, struct ssl_runtime_context *ssl_context, char *buff, int buff_len, enum ssl_interested_region output_region_mask, int thread_seq, const void *a_packet);
