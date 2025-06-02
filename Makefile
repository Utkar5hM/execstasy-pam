install:
	gcc -fPIC -c mypam.c base32.c -I.;
	gcc -shared -o mypam.so mypam.o base32.o -lpam;
	sudo cp mypam.so /lib64/security/mypam.so

test: install
	pamtester -v pamtester user authenticate
