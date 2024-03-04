CC=gcc

SRC=packet_capture.c sinapktcap.c 
OBJ=$(SRC:.c=.o)

all: sinapktcap

sinapktcap: $(OBJ)
	$(CC) $(OBJ) -o $@

clean:
	rm -rf $(OBJ)
