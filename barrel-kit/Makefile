CC_64      = x86_64-w64-mingw32-gcc
OBJCOPY_64 = x86_64-w64-mingw32-objcopy
CFLAGS     = -DWIN_X64 -O1 -fno-jump-tables -Wall -Wno-pointer-arith -Isrc -c
INITIAL_CHECKIN_DELAY_SECONDS ?= 0
LOADER_CFLAGS = $(CFLAGS) -DINITIAL_CHECKIN_DELAY_SECONDS=$(INITIAL_CHECKIN_DELAY_SECONDS)

OBJECTS = bin/loader.x64.o            \
          bin/services.x64.o          \
          bin/load_phantom.x64.o      \
          bin/pico.x64.o              \
          bin/hooks.x64.o             \
          bin/spoof_worker_thread.x64.o \
          bin/wininet_gate.x64.o      \
          bin/stitch_stub.x64.bin     \
          bin/cfg_gadgets.x64.o       \
          bin/sleep_kraken_adv.x64.o  \
          bin/cleanup.x64.o           \
          bin/crt.x64.o

all: $(OBJECTS)

.PHONY: all clean FORCE bin

# Recompile when the command-line delay changes.
FORCE:

bin:
	mkdir -p bin

bin/loader.x64.o: FORCE bin src/loader.c src/loader.h src/memory.h src/tcg.h
	$(CC_64) $(LOADER_CFLAGS) src/loader.c -o $@

bin/services.x64.o: bin src/services.c src/tcg.h
	$(CC_64) $(CFLAGS) src/services.c -o $@

bin/load_phantom.x64.o: bin src/load_phantom.c src/memory.h
	$(CC_64) $(CFLAGS) -fno-omit-frame-pointer src/load_phantom.c -o $@

bin/pico.x64.o: bin src/pico.c src/memory.h src/mask.h src/spoof.h src/cleanup.h src/cfg.h src/tcg.h
	$(CC_64) $(CFLAGS) src/pico.c -o $@

bin/hooks.x64.o: bin src/hooks.c src/spoof.h
	$(CC_64) $(CFLAGS) -DWININET_IMAGE_GATE=1 src/hooks.c -o $@

bin/spoof_worker_thread.x64.o: bin src/spoof_worker_thread.c src/spoof.h
	$(CC_64) $(CFLAGS) -fno-omit-frame-pointer -masm=intel src/spoof_worker_thread.c -o $@

bin/spoof_stitch.x64.o: bin src/spoof_stitch.c src/spoof.h
	$(CC_64) $(CFLAGS) -fno-omit-frame-pointer -masm=intel src/spoof_stitch.c -o $@

bin/wininet_gate.x64.o: bin src/spoof_stitch.c src/spoof.h
	$(CC_64) $(CFLAGS) -DSPOOF_STITCH_GATE_ONLY=1 -fno-omit-frame-pointer -masm=intel -shared src/spoof_stitch.c -o $@

bin/stitch_entry.x64.o: bin src/stitch_entry.c
	$(CC_64) $(CFLAGS) -fno-omit-frame-pointer -masm=intel src/stitch_entry.c -o $@

bin/stitch_stub.x64.bin: bin src/stitch_stub.S
	$(CC_64) -DWIN_X64 -c src/stitch_stub.S -o bin/stitch_stub.x64.o
	$(OBJCOPY_64) -O binary --only-section=.text bin/stitch_stub.x64.o $@

bin/cfg_gadgets.x64.o: bin src/cfg_gadgets.c src/cfg.h src/memory.h
	$(CC_64) $(CFLAGS) src/cfg_gadgets.c -o $@

bin/sleep_kraken_adv.x64.o: bin src/sleep_kraken_adv.c src/mask.h src/memory.h
	$(CC_64) $(CFLAGS) -fno-omit-frame-pointer src/sleep_kraken_adv.c -o $@

bin/cleanup.x64.o: bin src/cleanup.c src/cleanup.h src/memory.h src/cfg.h
	$(CC_64) $(CFLAGS) src/cleanup.c -o $@

bin/crt.x64.o: bin src/crt.c
	$(CC_64) $(CFLAGS) src/crt.c -o $@

clean:
	rm -f bin/*.o bin/*.bin
