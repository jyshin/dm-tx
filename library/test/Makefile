all: test_yogurt_lib

test_yogurt_lib: test_yogurt_lib.c ../libyogurt.a
	g++ -o test_yogurt_lib test_yogurt_lib.c ../libyogurt.a 

clean:
	rm -f *.o test_yogurt_lib
