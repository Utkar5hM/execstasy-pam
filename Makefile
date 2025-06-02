install:
	gcc -fPIC -c pamshi.c base32.c base32_prog.c cJSON.c qrcode.c -I.;
	gcc -shared -o pamshi.so pamshi.o base32.o base32_prog.o cJSON.o qrcode.o -lpam  -lcurl;
	sudo cp pamshi.so /lib64/security/pamshi.so

test: install
	sudo pamtester -v pamtester user authenticate
