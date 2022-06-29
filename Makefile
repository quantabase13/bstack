INC= -I /home/ho/user_mode_thread_lib/bstack/include

all: bstack.o netdev.o skbuff.o tap_init.o arp.o
	gcc -o  main bstack.o netdev.o skbuff.o tap_init.o arp.o ${INC} -g
bstack.o: 
	gcc  -c bstack.c ${INC} -g
netdev.o:
	gcc  -c netdev.c ${INC} -g
arp.o: 
	gcc  -c  arp.c  ${INC} -g
tap_init.o: 
	gcc -c  tap_init.c ${INC} -g
skbuff.o:
	gcc -c  skbuff.c ${INC} -g
clean:
	rm -f *.o