all: isotope_pp_lib_test

isotope_pp_lib_test: isotope_pp_lib_test.c ../libisotopepp.a
	g++ -o isotope_pp_lib_test isotope_pp_lib_test.c ../libisotopepp.a 
../libisotopepp.a: ../isotope_pp_lib.c ../isotope_pp_lib.h
	cd .. && $(MAKE)
clean:
	rm -f *.o isotope_pp_lib_test ../libisotopepp.a
