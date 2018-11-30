vpath %.a ../lib
vpath %.h ./inc

PAPP_PATH=/home/lishu/sapp_ntc/

#CFLAGS          =  -g3 -Wall -fPIC -Werror -O
#CFLAGS          =  -g3 -Wall -fPIC -O
CFLAGS          =  -g3 -Wall -fPIC
CFLAGS	       	+= $(INCLUDES)
CC              = g++
CCC             = g++
INCLUDES        = -I./inc/
INCLUDES        += -I/usr/include/MESA/

LIB		= -L./lib/ 
#LIB		+= -lopenssl 
LIB		+= /usr/lib64/ruby/openssl.so

LIB_FILE	= $(wildcard ../lib/*.a)
SOURCES		= $(wildcard *.c)
OBJECTS 	= $(SOURCES:.c=.o)
DEPS		= $(SOURCES:.c=.d)

TARGET		= ssl.so

.PHONY:clean all 

all:$(TARGET)

$(TARGET):$(OBJECTS) $(LIB_FILE)
	$(CCC) -shared $(CFLAGS) $(OBJECTS) $(LIB) -o $@  
	cp $(TARGET) ../bin/
	
.c.o:
%.d:%.c
	$(CCC) $< -MM $(INCLUDES) > $@

-include $(DEPS)

clean :
	rm -f $(OBJECTS) $(DEPS) $(TARGET) 


PLUGIN_PATH=./plug/protocol
CONFLIST_NAME=conflist_protocol.inf
PLUGIN_DIR_NAME=ssl
PLUGIN_INF_NAME=ssl.inf

TARGET_DIR=$(PAPP_PATH)/$(PLUGIN_PATH)/$(PLUGIN_DIR_NAME)/
INSERT_FILE=$(PAPP_PATH)/$(PLUGIN_PATH)/$(CONFLIST_NAME)
INSERT_CONTENT=$(PLUGIN_PATH)/$(PLUGIN_DIR_NAME)/$(PLUGIN_INF_NAME)
install:
	mkdir -p  $(TARGET_DIR) 
	cp -r ../bin/*.inf $(TARGET_DIR)
	cp -r ../bin/*.so $(TARGET_DIR)
	@ret=`cat $(INSERT_FILE)|grep $(INSERT_CONTENT)|wc -l`;if [ $$ret -eq 0 ];then echo $(INSERT_CONTENT) >>$(INSERT_FILE);fi
        
CONF_DIR=$(PAPP_PATH)/conf/
conf:
	mkdir -p  $(CONF_DIR) 
	cp -r ../bin/ssl $(CONF_DIR)   
