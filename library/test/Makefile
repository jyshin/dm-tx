CC 	:= gcc
CXX	:= g++
TARGETS	:= test_yogurt_lib test_isotope_lib

all: $(TARGETS)

test_yogurt_lib: test_yogurt_lib.cpp ../libyogurt.a
	$(CXX) -o test_yogurt_lib test_yogurt_lib.cpp -L.. -lyogurt 

test_isotope_lib: test_isotope_lib.c ../libisotope.a
	$(CC) -o test_isotope_lib test_isotope_lib.c -L.. -lisotope 

clean:
	rm -f *.o $(TARGETS)
