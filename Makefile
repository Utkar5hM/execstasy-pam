install:
	gcc -fPIC -c mypam.c base32.c base32_prog.c -I.;
	gcc -shared -o mypam.so mypam.o base32.o base32_prog.o -lpam  -lcurl;
	sudo cp mypam.so /lib64/security/mypam.so

test: install
	sudo pamtester -v pamtester user authenticate
