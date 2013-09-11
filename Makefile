all: tpmkey pkcs11
.PHONY: all pkcs11 clean

OBJS := init.o convert.o keyring.o keyfile.o newkey.o \
	utils.o tspi_helpers.o seedrng.o crypto_scrypt-sse.o \
	sha256.o

tpmkey: $(OBJS) main.o
	g++ -Wall -o $@ -g $^ -ltspi -lgnutls -lgcrypt

pkcs11: tpmkey-pkcs11.so
tpmkey-pkcs11.so: $(OBJS) p11_function_list.o p11_cxx.o
	g++ -shared -Wl,--no-undefined -o $@ $^ -ltspi -lgnutls -lgcrypt

%.o: %.cc *.h
	g++ -g -Wall -Werror=return-type -fvisibility=hidden -fvisibility-inlines-hidden -fPIC -c $<

%.o: %.c *.h
	gcc -std=gnu99 -g -Wall -Werror=return-type -fvisibility=hidden -fPIC -c $<

# Eww...
%.o: scrypt/%.c *.h
	gcc -std=gnu99 -O2 -Wall -Werror=return-type -fvisibility=hidden -fPIC -c $<

clean:
	rm -f *.o tpmkey tpmkey-pkcs11.so
