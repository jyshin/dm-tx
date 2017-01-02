CC 	:= gcc
CXX	:= g++

all: libyogurt.a libisotope.a
	$(MAKE) -C ./test	

yogurt_lib.o: yogurt_lib.cpp yogurt_lib.h
	$(CXX) -c yogurt_lib.cpp

isotope_lib.o: isotope_lib.c isotope_lib.h
	$(CC) -c isotope_lib.c

libyogurt.a: yogurt_lib.o
	ar rcs libyogurt.a yogurt_lib.o

libisotope.a: isotope_lib.o
	ar rcs libisotope.a isotope_lib.o
clean:
	rm -f *.o *.a
	$(MAKE) clean -C ./test
