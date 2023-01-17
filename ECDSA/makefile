# ECDSA make file


CC=		gcc
LDFLAGS=	-ldl
LINK=		gcc
OBJECTS = exerMain.o crypt.o util.o

CFLAGS = -c
TARGET = ECDSA


$(TARGET) : $(OBJECTS)
	$(CC) -o $(TARGET) $(OBJECTS) $(LIBINC) $(LDFLAGS)
exerMain.o: exerMain.c
	$(CC) -o exerMain.o $(CFLAGS) exerMain.c
crypt.o: crypt.c
	$(CC) -o crypt.o $(CFLAGS) crypt.c
util.o: util.c
	$(CC) -o util.o $(CFLAGS) util.c
clean:	
	rm -f  $(OBJECTS) core
