all: libyogurt.a
	$(MAKE) -C ./test	
yogurt_lib.o: yogurt_lib.c yogurt_lib.h
	g++ -c yogurt_lib.c
libyogurt.a: yogurt_lib.o
	ar rcs libyogurt.a yogurt_lib.o
clean:
	rm -f *.o *.a
	$(MAKE) clean -C ./test
