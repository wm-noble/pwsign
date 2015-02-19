
CC=clang

%.o: %.c
	$(CC) -o $@ -c $<

install: pwsign.o
	$(CC) -o ~/bin/pwsign pwsign.o

remove:
	rm ~/bin/pwsign

