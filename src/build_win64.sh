#!/bin/bash

set -e
set -x

HOST=x86_64-w64-mingw32
PREFIX=$(pwd)/build_win64/install_root
export PKG_CONFIG_LIBDIR=$PREFIX/lib/pkgconfig

mkdir -p $PREFIX
cd build_win64

# libusb
if [[ ! -f $PREFIX/lib/libusb-1.0.a ]]; then
	
	if [[ ! -f libusb-1.0.26.tar.bz2 ]]; then
		wget https://github.com/libusb/libusb/releases/download/v1.0.26/libusb-1.0.26.tar.bz2
		tar -xvjf libusb-1.0.26.tar.bz2
	fi
	
	cd libusb-1.0.26
	./configure --host=$HOST --prefix=$PREFIX --enable-static --disable-shared
	make -j4 install
	cd ..
fi

# hackrf
if [[ ! -f $PREFIX/lib/libhackrf.a ]]; then
	
	if [[ ! -f hackrf-2023.01.1.tar.xz ]]; then
		wget https://github.com/greatscottgadgets/hackrf/releases/download/v2023.01.1/hackrf-2023.01.1.tar.xz
		tar -xvJf hackrf-2023.01.1.tar.xz
	fi
	
	rm -rf hackrf-2023.01.1/host/libhackrf/build
	mkdir -p hackrf-2023.01.1/host/libhackrf/build
	cd hackrf-2023.01.1/host/libhackrf/build
	cmake .. \
		-DCMAKE_SYSTEM_NAME=Windows \
		-DCMAKE_C_COMPILER=$HOST-gcc \
		-DCMAKE_INSTALL_PREFIX=$PREFIX \
		-DCMAKE_INSTALL_LIBPREFIX=$PREFIX/lib \
		-DLIBUSB_INCLUDE_DIR=$PREFIX/include/libusb-1.0 \
		-DLIBUSB_LIBRARIES=$PREFIX/lib/libusb-1.0.a
	make -j4 install
	cd ../../../..
	mv $PREFIX/bin/*.a $PREFIX/lib/
	find $PREFIX -name libhackrf\*.dll\* -delete
fi

# osmo-fl2k
if [[ ! -f $PREFIX/lib/libosmo-fl2k.a ]]; then
	
	if [[ ! -d osmo-fl2k ]]; then
		git clone --depth 1 https://gitea.osmocom.org/sdr/osmo-fl2k.git
		# Patch for compilation error on more modern versions of GCC
		cd osmo-fl2k/src/getopt/
		wget -O - https://lists.osmocom.org/hyperkitty/list/osmocom-sdr@lists.osmocom.org/message/KGOKNLMLIEECP4I5QQJE6JICFP3V2GAP/attachment/2/osmo-fl2k-getopts-args.patch | patch
		cd ../../..
	fi
	
	rm -rf osmo-fl2k/build
	mkdir -p osmo-fl2k/build
	cd osmo-fl2k/build
	cmake .. \
		-DCMAKE_SYSTEM_NAME=Windows \
		-DCMAKE_C_COMPILER=$HOST-gcc \
		-DCMAKE_INSTALL_PREFIX=$PREFIX \
		-DCMAKE_INSTALL_LIBPREFIX=$PREFIX \
		-DCMAKE_INSTALL_LIBDIR=$PREFIX/lib \
		-DLIBUSB_INCLUDE_DIR=$PREFIX/include/libusb-1.0 \
		-DLIBUSB_LIBRARIES=$PREFIX/lib/libusb-1.0.a
	make -j4 install
	cd ../..
	mv $PREFIX/lib/liblibosmo-fl2k_static.a $PREFIX/lib/libosmo-fl2k.a
fi

# AAC codec
if [[ ! -f $PREFIX/lib/libfdk-aac.a ]]; then
	
	if [[ ! -d fdk-aac ]]; then
		git clone --depth 1 https://github.com/mstorsjo/fdk-aac.git
	fi
	
	cd fdk-aac
	./autogen.sh
	./configure --host=$HOST --prefix=$PREFIX --enable-static --disable-shared
	make -j4 install
	cd ..
fi

# opus codec
if [[ ! -f $PREFIX/lib/libopus.a ]]; then
	
	if [[ ! -f opus-1.4.tar.gz ]]; then
		wget https://downloads.xiph.org/releases/opus/opus-1.4.tar.gz
		tar -xvzf opus-1.4.tar.gz
	fi
	
	cd opus-1.4
	./configure --host=$HOST --prefix=$PREFIX --enable-static --disable-shared --disable-doc --disable-extra-programs
	make -j4 install
	cd ..
fi

# freetype2, required for subtitles and timestamp
if [[ ! -f $PREFIX/lib/libfreetype.a ]]; then

    	if [[ ! -d freetype ]]; then
		git clone --depth 1 https://gitlab.freedesktop.org/freetype/freetype.git
	fi

    	cd freetype
    	./autogen.sh
    	./configure --prefix=$PREFIX --disable-shared --with-pic --host=$HOST --without-zlib --with-png=no --with-harfbuzz=no
    	make -j4 install
    	cd ..
fi

# zlib, required for logo support
if [[ ! -f $PREFIX/lib/libz.a ]]; then

	if [[ ! -d zlib ]]; then
		git clone --depth 1 https://github.com/madler/zlib.git
	fi

	cd zlib
	CC=$HOST-gcc AR=$HOST-ar RANLIB=$HOST-ranlib \
	./configure --prefix=$PREFIX --static
	make -j4 install
	cd ..
fi

# libpng, also required for logo support
if [[ ! -f $PREFIX/lib/libpng16.a ]]; then

	if [[ ! -d libpng ]]; then
		git clone --depth 1 https://github.com/glennrp/libpng.git
	fi

	cd libpng
	CPPFLAGS="-I$PREFIX/include" LDFLAGS="-L$PREFIX/lib" \
	./configure --prefix=$PREFIX --host=$HOST
 	make -j4 install
	cd ..
fi

# libiconv, pre-requisite for zvbi
if [[ ! -f $PREFIX/lib/libiconv.a ]]; then

	if [[ ! -f libiconv-1.17.tar.gz ]]; then
		wget https://ftp.gnu.org/gnu/libiconv/libiconv-1.17.tar.gz
		tar xzvf libiconv-1.17.tar.gz
	fi

	cd libiconv-1.17
	./configure --prefix=$PREFIX --host=$HOST --enable-static --disable-shared
	make -j4 install
	cd ..
fi

# zvbi, required for handling teletext subtitles in transport streams
if [[ ! -f $PREFIX/lib/libzvbi.a ]]; then

	if [[ ! -f v0.2.43.zip ]]; then
		wget https://github.com/zapping-vbi/zvbi/archive/refs/tags/v0.2.43.zip
		unzip v0.2.43.zip
		cd zvbi-0.2.43
	fi

	./autogen.sh
	CPPFLAGS="-I$PREFIX/include" LDFLAGS="-L$PREFIX/lib" \
	./configure \
	--prefix=$PREFIX --host=$HOST --enable-static --disable-shared --disable-dvb \
	--disable-bktr --disable-proxy --disable-nls --without-doxygen --without-libiconv-prefix 
	make -j4 install
	cd ..
fi

# termiWin
if [[ ! -f $PREFIX/lib/libtermiwin.a ]]; then

	if [[ ! -d termiwin ]]; then
		git clone --depth 1 https://github.com/steeviebops/termiWin.git termiwin
	fi

	rm -rf termiwin/build
	mkdir -p termiwin/build
	cd termiwin/build
	cmake .. \
		-DCMAKE_SYSTEM_NAME=Windows \
		-DCMAKE_C_COMPILER=$HOST-gcc \
		-DCMAKE_CXX_COMPILER=$HOST-g++ \
		-DCMAKE_INSTALL_PREFIX=$PREFIX \
		-DTERMIWIN_DONOTREDEFINE=yes
	make -j4 install
	cd ../..
fi

# ffmpeg
if [[ ! -f $PREFIX/lib/libavformat.a ]]; then
	
	if [[ ! -d ffmpeg ]]; then
		git clone --depth 1 --branch n6.1.1 https://github.com/FFmpeg/FFmpeg.git ffmpeg
	fi
	
	cd ffmpeg
	./configure \
		--enable-gpl --enable-nonfree --enable-libfdk-aac --enable-libopus \
		--enable-static --disable-shared --disable-programs --enable-zlib \
		--enable-libfreetype --enable-libzvbi --disable-outdevs --disable-encoders \
		--arch=x86_64 --target-os=mingw64 --cross-prefix=$HOST- \
		--pkg-config=pkg-config --prefix=$PREFIX --extra-ldflags="-fstack-protector"
	make -j4 install
	cd ..
fi

cd ..
CROSS_HOST=$HOST- make -j4 EXTRA_LDFLAGS="-static -fstack-protector" EXTRA_PKGS="libtermiwin libusb-1.0"
$HOST-strip hacktv.exe

echo "Done"
