CXXFLAGS	+=	-std=c++11 -I./include -I/usr/local/include -I/usr/include
LIBS		+=	-lsodium -lsqlite3
LDFLAGS		+= 	-L./lib -L/usr/local/lib -L/usr/lib

all: alert
bsd: bsddepends bsdjazmine_a
linux: linuxdepends linuxjazmine_a
.PHONY: all clean libsodium

alert:
	@echo '...'
	@echo 'compile with make bsd or make linux'
	@echo 'if your libsodium-dev package is outdated do a make libsodium'
	@echo '...'

bsdjazmine_a:
	$(CXX) $(CXXFLAGS) -c base64/base64.cpp jazmine_a.cc
	$(CXX) -pthread -static $(LDFLAGS) -o ./bin/jazmine_a jazmine_a.o base64.o -lcares -ljsoncpp -lz $(LIBS)
	$(CC) -o ./bin/jazcli jazcli.c

linuxjazmine_a:
	$(CXX) $(CXXFLAGS) -c base64/base64.cpp jazmine_a.cc
	$(CXX) -pthread -static $(LDFLAGS) -o ./bin/jazmine_a jazmine_a.o base64.o -lcares -ljsoncpp -lz -lev $(LIBS) -ldl
	$(CC) -o ./bin/jazcli jazcli.c

bsddepends:
	mkdir -p ./bin
	mkdir -p ./include
	mkdir -p ./lib
	mkdir -p ./jsoncpp-1.8.4/build
	cd ./jsoncpp-1.8.4/build && cmake .. && make
	cp -a ./jsoncpp-1.8.4/build/src/lib_json/libjsoncpp.a ./lib
	cp -a ./jsoncpp-1.8.4/include/json ./include
	cd ./c-ares-1.14.0 && ./configure && make
	cp ./c-ares-1.14.0/*.h ./include
	cp ./c-ares-1.14.0/.libs/libcares.a ./lib
	cp ./base64/base64.h ./include
	
linuxdepends:
	mkdir -p ./bin
	mkdir -p ./include
	mkdir -p ./lib
	mkdir -p ./jsoncpp-1.8.4/build
	cd ./jsoncpp-1.8.4/build && cmake .. && make
	cp ./jsoncpp-1.8.4/build/src/lib_json/libjsoncpp.a ./lib
	cp -a ./jsoncpp-1.8.4/include/json ./include
	cd ./c-ares-1.14.0 && ./configure && make
	cp ./c-ares-1.14.0/*.h ./include
	cp ./c-ares-1.14.0/.libs/libcares.a ./lib
	cp ./base64/base64.h ./include

libsodium:
	mkdir -p ./include
	mkdir -p ./lib
	cd ./libsodium-1.0.16 && ./autogen.sh && ./configure && make
	cp ./libsodium-1.0.16/src/libsodium/.libs/libsodium.a ./lib
	cp -a ./libsodium-1.0.16/src/libsodium/include/sodium ./include
	cp ./libsodium-1.0.16/src/libsodium/include/sodium.h ./include

clean:
	rm -f *.o
	rm -f *.core
	cd ./c-ares-1.14.0 && make distclean
	cd ./libsodium-1.0.16 && make clean
	rm -Rf ./include
	rm -Rf ./lib
	rm -Rf ./bin
	rm -Rf ./jsoncpp-1.8.4/build

wipe:
	rm -f *.db
	rm -f *.json
