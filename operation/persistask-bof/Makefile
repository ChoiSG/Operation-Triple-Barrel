BOFNAME := persistask
COMINCLUDE := -I ./common
LIBINCLUDE := -l oleaut32 -l ole32 -l secur32 -l advapi32
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
CC := x86_64-w64-mingw32-clang

all:
	$(CC_x64) -o $(BOFNAME).x64.o $(COMINCLUDE) -Os -c $(BOFNAME).c -DBOF
	$(CC_x86) -o $(BOFNAME).x86.o $(COMINCLUDE) -Os -c $(BOFNAME).c -DBOF

dist: all
	mkdir -p _bin
	cp $(BOFNAME).x64.o _bin/
	cp $(BOFNAME).x86.o _bin/

test:
	$(CC_x64) $(BOFNAME).c $(COMINCLUDE) $(LIBINCLUDE) -o $(BOFNAME).x64.exe
	$(CC_x86) $(BOFNAME).c $(COMINCLUDE) $(LIBINCLUDE) -o $(BOFNAME).x86.exe

scanbuild:
	$(CC) $(BOFNAME).c $(COMINCLUDE) $(LIBINCLUDE) -o $(BOFNAME).scanbuild.exe

check:
	cppcheck --enable=all --suppress=missingIncludeSystem --suppress=unusedFunction $(COMINCLUDE) --platform=win64 $(BOFNAME).c

clean:
	rm -f $(BOFNAME).*.o $(BOFNAME).*.exe
	rm -f _bin/*.o