# CREATED by Guo Le, 08/23/2010
#
CC		=   gcc
PROGRAM = test_cert
CFLAGS  = -g -Wall 
INCLUDE = -I. -I./common 
LDFLAGS	= 	-lpthread -Wall 
OBJS 	= backend.o	 
DEPLOY_DIR = /home/ictsoft/fake_backend
BUILD_DIR = ./debug
LIB = /usr/lib64/ruby/openssl.so

.PHONY : all clean 
all: $(PROGRAM) 


test_cert: test_cert.c
	gcc  $(INCLUDE) $(LDFLAGS) -g -Wall test_cert.c $(LIB) -lcrypto  -o cert_test

$(OBJS): %.o: %.c 
	$(CC) -c $(CFLAGS) $(INCLUDE) $< -o $@


clean:
	$(RM) *.o $(PROGRAM)

localdeploy: $(PROGRAM)
	@echo "- Kill previous process ---------------------------------------------"
	@-killall -vq backend_video backend_audio;
	@echo "---------------------------------------------------------------------"
	@echo "- Check deploy dir --------------------------------------------------"
	@if [ ! -d "$(DEPLOY_DIR)" ]; \
	then echo "DEPLOY_DIR doesn't exist!"; mkdir -p $(DEPLOY_DIR); \
 	else echo "DEPLOY_DIR exist, remove all"; fi
	@-rm -rfv $(DEPLOY_DIR)/*
	@echo "---------------------------------------------------------------------"
	@echo "- Deploy ------------------------------------------------------------"
	@cp -rv $(BUILD_DIR)/* $(DEPLOY_DIR)
	@echo "---------------------------------------------------------------------"
	@echo "- Run ---------------------------------------------------------------"
	@cd $(DEPLOY_DIR); ./r2;
	@ps au | grep -e "backend" | grep -v grep 
