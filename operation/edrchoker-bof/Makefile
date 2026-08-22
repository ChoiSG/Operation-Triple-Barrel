BOFNAME := edrchoker
COMINCLUDE := -I ./common
CC_x64 := x86_64-w64-mingw32-gcc

CFLAGS := -masm=intel -Wall -Os -mno-stack-arg-probe

all:
	$(CC_x64) -o $(BOFNAME).x64.o $(COMINCLUDE) $(CFLAGS) -c entry.c -DBOF

dist: all
	mkdir -p _bin
	cp $(BOFNAME).x64.o _bin/

clean:
	rm -f $(BOFNAME).*.o
	rm -f _bin/*.o
