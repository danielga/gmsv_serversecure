#!/bin/sh

export GARRYSMOD_COMMON=$HOME/garrysmod_common
export SOURCE_SDK=$HOME/sourcesdk

if [[ ${TRAVIS_OS_NAME} = osx ]]; then
	PREMAKE_CORE=premake-core-macosx.tar.bz2
	export PREMAKE5=$HOME/premake-core/premake5
	export CXX=g++-4.8
	export CC=gcc-4.8
elif [[ ${TRAVIS_OS_NAME} = linux ]]; then
	PREMAKE_CORE=premake-core-linux.tar.bz2
	export PREMAKE5=$HOME/premake-core/premake5
	export CXX=g++-5
	export CC=gcc-5
fi

# if any line errors, stop script immediately
set -e

cd $HOME

# if the garrysmod_common dir is empty (isn't cached yet), then git clone the repo
# otherwise, cd to it, pull the latest commit and update all of its submodules
if [ ! -d "garrysmod_common/premake5.lua" ]; then
	echo "garrysmod_common directory is empty, doing git clone of the remote repo"
	git clone --recursive https://bitbucket.org/danielga/garrysmod_common.git
else
	echo "garrysmod_common directory is good, pulling any latest changes"
	cd garrysmod_common
	git pull
	git submodule update --init --recursive
	cd ..
fi

# if the sourcesdk dir is empty (isn't cached yet), then wget the tar and extract it
if [ ! -d "sourcesdk/public" ]; then
	echo "sourcesdk directory is empty, doing wget and untar"
	wget https://bitbucket.org/danielga/garrysmod_common/downloads/sourcesdk.tar.bz2
	tar -jxvf sourcesdk.tar.bz2
fi

# if the premake-core dir is empty (isn't cached yet), then wget the tar and extract it
# then cd to its dir, make, go back up and copy the executable to premake-core
if [ ! -d "premake-core/premake5" ]; then
	echo "premake-core directory is empty, doing wget, untar, make and copy"
	wget https://bitbucket.org/danielga/garrysmod_common/downloads/$PREMAKE_CORE
	tar -jxvf $PREMAKE_CORE
	mv premake-core premake-core-build
	cd premake-core-build
	make
	cd ..
	mkdir premake-core
	cp premake-core-build/bin/release/premake5 premake-core
fi
