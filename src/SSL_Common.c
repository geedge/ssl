/*
 * SSL_Common.c

 *
 *  Created on: 2013-5-8
 *      Author: lis
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "SSL_Common.h"

int get_so_path(void* func_addr,char* path,unsigned int size)
 
 {
 
		  Dl_info av_dl_info;
 
		  dladdr(func_addr,&av_dl_info);
 
		  unsigned int i=0,last_slash_pos=0;
 
		  for(i=0;i<strlen(av_dl_info.dli_fname);i++)
 
		  {
 
					if(av_dl_info.dli_fname[i]=='/')
 
					{
 
							 last_slash_pos=i;
 
					}
 
		  }
 
		  if(i<size)
 
		  {
 
					memcpy(path,av_dl_info.dli_fname,last_slash_pos);
 
					return last_slash_pos;
 
		  }
 
		  else
 
		  {
 
					return 0;
 
		  }
 
  
 
 }
 

