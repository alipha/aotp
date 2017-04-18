#include <stdio.h>
#include <stdlib.h>
#include <limits.h>


int usage(const char *prog_name);
int generate_pad(FILE *fp, long int requested);


int main(int argc, char **argv) {
	long int requested;
	char *end_ptr;
	FILE *fp;
	int error;

	if(argc != 2) {
		if(argc == 1)
			fprintf(stderr, "\nToo few arguments: ");
		else
			fprintf(stderr, "\nToo many arguments: ");

		fprintf(stderr, "%s expects exactly one argument to be provided.\n\n", argv[0]);
		return usage(argv[0]);
	}

	requested = strtol(argv[1], &end_ptr, 10);
	
	if(*end_ptr != '\0' || requested <= 0 || requested > (LONG_MAX >> 8)) {
		fprintf(stderr, "You must provide a valid integer to %s between 1 and %ld.\n\n", argv[0], LONG_MAX >> 8);
		return usage(argv[0]);
	}

	fp = fopen("/dev/urandom", "rb");

	if(!fp) {
		fprintf(stderr, "\nUnable to open /dev/urandom.\n\n");
		return 2;
	}

	error = generate_pad(fp, requested);
	fclose(fp);

	return error;
}


int usage(const char *prog_name) {
	fprintf(stderr, "Usage: %s BYTES\n\n", prog_name);
	fprintf(stderr, "Generates a one-time-pad from /dev/urandom which is large enough to\n");
	fprintf(stderr, "encrypt a message of length BYTES. The actual one-time-pad will be\n");
	fprintf(stderr, "256 times larger. The one-time-pad will be written to stdout.\n\n");
	return 1;
}


int generate_pad(FILE *fp, long int requested) {
	unsigned char bytes[256];

	for(long int read = 0; read < requested; read++) {
		if(fread(bytes, sizeof bytes, 1, fp) != 1) {
			fprintf(stderr, "\nError reading from /dev/urandom.\n\n");
			return 3;
		}
		if(fwrite(bytes, sizeof bytes, 1, stdout) != 1) {
			fprintf(stderr, "\nError writing to stdout.\n\n");
			return 4;
		}
	}

	return 0;
}

