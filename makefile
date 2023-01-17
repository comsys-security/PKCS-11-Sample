# PKCS#11 Sample make file


CC=		gcc
LDFLAGS=	-ldl
LINK=		gcc
OBJECTS = nShieldPKCS11ChangLabel nShieldPKCS11FindKey nShieldPKCS11Login nShieldPKCS11RowSign PKCS11FindKey_Label nShieldPKCS11AESImport nShieldPKCS11DeleteKey nShieldPKCS11GenAESkey nShieldPKCS11RSASign nShieldPKCS11AESencrypt nShieldPKCS11ECDSASign nShieldPKCS11GenRSAkey nShieldPKCS11Random
CFLAGS = -c

all: nShieldPKCS11ChangLabel nShieldPKCS11FindKey nShieldPKCS11Login nShieldPKCS11RowSign PKCS11FindKey_Label nShieldPKCS11AESImport nShieldPKCS11DeleteKey nShieldPKCS11GenAESkey nShieldPKCS11RSASign nShieldPKCS11AESencrypt nShieldPKCS11ECDSASign nShieldPKCS11GenRSAkey nShieldPKCS11Random

nShieldPKCS11ChangLabel: nShieldPKCS11ChangLabel.c
	$(CC) -o $@ $(CFLAGS) $< $(LIBINC) $(LDFLAGS)
nShieldPKCS11FindKey: nShieldPKCS11FindKey.c
	$(CC) -o $@ $(CFLAGS) $< $(LIBINC) $(LDFLAGS)
nShieldPKCS11Login: nShieldPKCS11Login.c
	$(CC) -o $@ $(CFLAGS) $< $(LIBINC) $(LDFLAGS)
nShieldPKCS11RowSign: nShieldPKCS11RowSign.c
	$(CC) -o $@ $(CFLAGS) $< $(LIBINC) $(LDFLAGS)
PKCS11FindKey_Label: PKCS11FindKey_Label.c
	$(CC) -o $@ $(CFLAGS) $< $(LIBINC) $(LDFLAGS)
nShieldPKCS11AESImport: nShieldPKCS11AESImport.c
	$(CC) -o $@ $(CFLAGS) $< $(LIBINC) $(LDFLAGS)
nShieldPKCS11DeleteKey: nShieldPKCS11DeleteKey.c
	$(CC) -o $@ $(CFLAGS) $< $(LIBINC) $(LDFLAGS)
nShieldPKCS11GenAESkey: nShieldPKCS11GenAESkey.c
	$(CC) -o $@ $(CFLAGS) $< $(LIBINC) $(LDFLAGS)
nShieldPKCS11RSASign: nShieldPKCS11RSASign.c
	$(CC) -o $@ $(CFLAGS) $< $(LIBINC) $(LDFLAGS)
nShieldPKCS11AESencrypt: nShieldPKCS11AESencrypt.c
	$(CC) -o $@ $(CFLAGS) $< $(LIBINC) $(LDFLAGS)
nShieldPKCS11ECDSASign: nShieldPKCS11ECDSASign.c
	$(CC) -o $@ $(CFLAGS) $< $(LIBINC) $(LDFLAGS)
nShieldPKCS11GenRSAkey: nShieldPKCS11GenRSAkey.c
	$(CC) -o $@ $(CFLAGS) $< $(LIBINC) $(LDFLAGS)
nShieldPKCS11Random: nShieldPKCS11Random.c
	$(CC) -o $@ $(CFLAGS) $< $(LIBINC) $(LDFLAGS)
clean:	
	rm -f $(OBJECTS) core
