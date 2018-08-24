
#-finstrument-functions -lSaturn -pg 
# -O3 

all: cpor-misc.o cpor.h cpor-core.o cpor-app.c cpor-file.o cpor-keys.o cpor-app.c
	gcc -g -Wno-deprecated-declarations -Wall -lpthread -lcrypto -o cpor cpor-app.c cpor-core.o cpor-misc.o cpor-file.o cpor-keys.o

cpor-core.o: cpor-core.c cpor.h
	gcc -Wno-deprecated-declarations -g -Wall -c cpor-core.c

cpor-misc.o: cpor-misc.c cpor.h
	gcc -Wno-deprecated-declarations -g -Wall -c cpor-misc.c

cpor-file.o: cpor-file.c cpor.h
	gcc -Wno-deprecated-declarations -g -Wall -c cpor-file.c

cpor-keys.o: cpor-keys.c cpor.h
	gcc -Wno-deprecated-declarations -g -Wall -c cpor-keys.c

cporlib: cpor-core.o cpor-misc.o
	ar -rv cporlib.a cpor-core.o cpor-misc.o

clean:
	rm -rf *.o *.tag *.t cpor.dSYM cpor cpor-m cpor.key
