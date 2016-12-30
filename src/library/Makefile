all: libisotopepp.a
	$(MAKE) -C ./test	
isotope_pp_lib.o: isotope_pp_lib.c isotope_pp_lib.h
	g++ -c isotope_pp_lib.c
libisotopepp.a: isotope_pp_lib.o
	ar rcs libisotopepp.a isotope_pp_lib.o
clean:
	rm -f *.o *.a
	$(MAKE) clean -C ./test
