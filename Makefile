obj-m += sys_queue.o
# sys_queue-objs := xcrypt.o
INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

ifdef ADD_DELAY
ADD_DELAY_FLAG := -DADD_DELAY=1
endif

ifdef ADD_PROGRESS
ADD_PROGRESS_FLAG := -DADD_PROGRESS=1
endif

all: xhw3 queue

socket.o: socket.c
	gcc -Wall -Werror -c socket.c

xhw3: xhw3.c socket.o
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi xhw3.c socket.o -lpthread -lssl -lcrypto -o xhw3

queue:
	KCPPFLAGS="$(ADD_DELAY_FLAG) $(ADD_PROGRESS_FLAG)" make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f xhw3