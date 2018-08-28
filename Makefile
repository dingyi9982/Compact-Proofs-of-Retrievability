
#-finstrument-functions -lSaturn -pg 
# -O3 

# all: cpor-genaro.o cpor-misc.o cpor.h cpor-core.o cpor-file.o cpor-keys.o
#	gcc -g -Wno-deprecated-declarations -Wall -lpthread -lcrypto -o cpor cpor-genaro.c cpor-core.o cpor-misc.o cpor-file.o cpor-keys.o

libcpor: cpor-genaro.o cpor-misc.o cpor-core.o cpor-file.o cpor-keys.o
	ar -rv libcpor.a cpor-genaro.o cpor-misc.o cpor-core.o cpor-file.o cpor-keys.o
	
cpor-genaro.o: cpor-genaro.c cpor.h
	gcc -Wno-deprecated-declarations -g -Wall -c cpor-genaro.c

cpor-core.o: cpor-core.c cpor.h
	gcc -Wno-deprecated-declarations -g -Wall -c cpor-core.c

cpor-misc.o: cpor-misc.c cpor.h
	gcc -Wno-deprecated-declarations -g -Wall -c cpor-misc.c

cpor-file.o: cpor-file.c cpor.h
	gcc -Wno-deprecated-declarations -g -Wall -c cpor-file.c

cpor-keys.o: cpor-keys.c cpor.h
	gcc -Wno-deprecated-declarations -g -Wall -c cpor-keys.c

clean:
	rm -rf *.o *.tag *.t cpor.dSYM libcpor.a
