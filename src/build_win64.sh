#!/bin/bash

set -e
set -x

HOST=x86_64-w64-mingw32
PREFIX=$(pwd)/build_win64/install_root
export PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig

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
	mingw64-cmake \
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
		git clone --depth 1 git://git.osmocom.org/osmo-fl2k
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

	if [[ ! -f zvbi-0.2.35.tar.bz2 ]]; then
		wget https://download.sourceforge.net/project/zapping/zvbi/0.2.35/zvbi-0.2.35.tar.bz2
		tar xjvf zvbi-0.2.35.tar.bz2
		# Can't be cross compiled in its default state, needs to be patched first
		# This repo contains the patch files that we need
		git clone --depth 1 https://github.com/rdp/ffmpeg-windows-build-helpers.git
		cd zvbi-0.2.35
		patch -p0 < ../ffmpeg-windows-build-helpers/patches/zvbi-win32.patch
		patch < ../ffmpeg-windows-build-helpers/patches/zvbi-no-contrib.diff
	fi

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
		git clone --depth 1 https://github.com/FFmpeg/FFmpeg.git ffmpeg
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
