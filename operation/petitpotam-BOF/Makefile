BOFNAME := petitpotam
COMINCLUDE := -I ./common
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc

all:
	mkdir -p _bin
	$(CC_x64) -o _bin/$(BOFNAME).x64.o $(COMINCLUDE) -I ./ -Os -c $(BOFNAME).c -DBOF
	$(CC_x86) -o _bin/$(BOFNAME).x86.o $(COMINCLUDE) -I ./ -Os -c $(BOFNAME).c -DBOF -DWOW64

clean:
	rm -f _bin/*.o
