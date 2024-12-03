install:
	gcc -fPIC -c mypam.c;
	gcc -shared -o mypam.so mypam.o -lpam;
	sudo cp mypam.so /lib64/security/mypam.so

test:
	pamtester -v pamtester user authenticate
