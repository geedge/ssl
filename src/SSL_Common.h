/*
 * SSL_Common.h

 *
 *  Created on: 2013-5-8
 *      Author: lis
 */

#ifndef SSL_COMMON_H_
#define SSL_COMMON_H_

#include <time.h>
#include <ctype.h>
#include <dlfcn.h>

#ifdef __cplusplus
extern "C" {
#endif
int get_so_path(void* func_addr,char* path,unsigned int size);

#ifdef __cplusplus
}
#endif
#endif /* SSL_COMMON_H_ */
