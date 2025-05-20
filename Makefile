iall: 1m-block

1m-block: 1m-block.o
	gcc -o 1m-block 1m-block.o -lnetfilter_queue

1m-block.o: 1m-block.c

clean:
	rm -f 1m-block *.o
