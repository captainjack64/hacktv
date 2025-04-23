
VERSION := $(shell git log -1 --pretty='%cd' --date=format:'%Y%m%d')-$(shell git describe --dirty --always)
CC      := $(CROSS_HOST)gcc
PKGCONF := pkg-config
CFLAGS  := -g -Wall -Wno-unused-result -pthread -O3 $(EXTRA_CFLAGS) -DVERSION=\"$(VERSION)\"
LDFLAGS := -g -lm -lz -lpng16 -pthread $(EXTRA_LDFLAGS)
OBJS    := fifo.o vitc.o hacktv.o common.o fir.o vbidata.o teletext.o wss.o video.o mac.o dance.o videocrypt.o videocrypts.o videocrypt-ca.o syster.o syster-ca.o acp.o vits.o nicam728.o sis.o av.o av_test.o av_ffmpeg.o rf_file.o font.o subtitles.o eurocrypt.o graphics.o keyboard.o rf.o spdif.o cc608.o
PKGS    := libpng libavcodec libavformat libavdevice libswscale libswresample libavutil libhackrf libavfilter freetype2 $(EXTRA_PKGS)

HACKRF := $(shell $(PKGCONF) --exists libhackrf && echo hackrf)
ifeq ($(HACKRF),hackrf)
	OBJS += rf_hackrf.o
	PKGS += libhackrf
	CFLAGS += -DHAVE_HACKRF
endif

SOAPYSDR := $(shell $(PKGCONF) --exists SoapySDR && echo SoapySDR)
ifeq ($(SOAPYSDR),SoapySDR)
	OBJS += rf_soapysdr.o
	PKGS += SoapySDR
	CFLAGS += -DHAVE_SOAPYSDR
endif

FL2K := $(shell $(PKGCONF) --exists libosmo-fl2k && echo fl2k)
ifeq ($(FL2K),fl2k)
	OBJS += rf_fl2k.o
	PKGS += libosmo-fl2k
	CFLAGS += -DHAVE_FL2K
endif

CFLAGS  += $(shell $(PKGCONF) --cflags $(PKGS))
LDFLAGS += $(shell $(PKGCONF) --libs $(PKGS))

all: hacktv

hacktv: $(OBJS)
	$(CC) -o hacktv $(OBJS) $(LDFLAGS)

%.o: %.c Makefile
	$(CC) $(CFLAGS) -c $< -o $@
	@$(CC) $(CFLAGS) -MM $< -o $(@:.o=.d)

install:
	cp -f hacktv $(PREFIX)/usr/local/bin/

clean:
	rm -f *.o *.d hacktv hacktv.exe

-include $(OBJS:.o=.d)

