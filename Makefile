EXENAME := createProcess
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
STRIP_x64 := x86_64-w64-mingw32-strip
STRIP_x86 := i686-w64-mingw32-strip
OPTIONS := -masm=intel -Wall -I include

createprocess: clean
	$(info ###### RELEASE ######)

	$(CC_x64) source/main.c source/syscalls.c source/dinvoke.c -o dist/$(EXENAME).x64.exe $(OPTIONS)
	$(STRIP_x64) --strip-all dist/$(EXENAME).x64.exe

#	$(CC_x86) source/main.c source/syscalls.c source/dinvoke.c -o dist/$(EXENAME).x86.exe $(OPTIONS)
#	$(STRIP_x86) --strip-all dist/$(EXENAME).x86.exe

debug: clean
	$(info ###### DEBUG ######)

	$(CC_x64) source/main.c source/syscalls.c source/dinvoke.c -o dist/$(EXENAME).x64.exe $(OPTIONS) -DDEBUG

#	$(CC_x86) source/main.c source/syscalls.c source/dinvoke.c -o dist/$(EXENAME).x86.exe $(OPTIONS) -DDEBUG

clean:
	rm -f dist/*
