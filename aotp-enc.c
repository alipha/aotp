#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


int usage(const char *prog_name);
int encrypt(FILE *otp_file, const char *otp_filename);
void encrypt_byte(uint32_t *encrypted_words, const uint32_t *otp_words, unsigned char plaintext_byte);


int main(int argc, char **argv) {
	FILE *otp_file;
	int error;

	if(argc != 2) {
		if(argc == 1)
			fprintf(stderr, "\nToo few arguments: ");
		else
			fprintf(stderr, "\nToo many arguments: ");

		fprintf(stderr, "%s expects exactly one argument to be provided.\n\n", argv[0]);
		return usage(argv[0]);
	}

	otp_file = fopen(argv[1], "rb");

	if(!otp_file) {
		fprintf(stderr, "\nUnable to open \"%s\".\n\n", argv[1]);
		return 2;
	}

	error = encrypt(otp_file, argv[1]);
	fclose(otp_file);

	return error;
}


int usage(const char *prog_name) {
	fprintf(stderr, "Usage: %s OTP-FILE\n\n", prog_name);
	fprintf(stderr, "Encrypts the input from stdin using the provided OTP-FILE file.\n");
	fprintf(stderr, "The input to be encrypted must not be more than 1/256th the length of\n");
	fprintf(stderr, "the OTP-FILE file. The encrypted output will be written to stdout.\n\n");
	return 1;
}


int encrypt(FILE *otp_file, const char *otp_filename) {
	uint32_t encrypted_words[32];
	uint32_t otp_words[64];
	int plaintext_byte;

	while((plaintext_byte = fgetc(stdin)) != EOF) {
		if(fread(otp_words, sizeof otp_words, 1, otp_file) != 1) {
			if(feof(otp_file)) {
				fprintf(stderr, "\n\"%s\" is not long enough to encrypt the input.\n\n", otp_filename);
				return 3;
			}

			fprintf(stderr, "\nError reading from \"%s\".\n\n", otp_filename);
			return 4;
		}

		encrypt_byte(encrypted_words, otp_words, (unsigned char)plaintext_byte);

		if(fwrite(encrypted_words, sizeof encrypted_words, 1, stdout) != 1) {
			fprintf(stderr, "\nError writing to stdout.\n\n");
			return 5;
		}
	}

	if(ferror(stdin)) {
		fprintf(stderr, "\nError reading from stdin.\n\n");
		return 6;
	}

	return 0;
}


void encrypt_byte(uint32_t *encrypted_words, const uint32_t *otp_words, unsigned char plaintext_byte) {
	uint32_t bit;
	uint32_t bit_mask;
	uint32_t inverse_mask;

	for(int bit_pos = 0; bit_pos < 8; bit_pos++) {
		bit = (plaintext_byte & (1 << bit_pos)) >> bit_pos;
		bit_mask = (bit - 1) ^ 0x55555555;
		inverse_mask = bit_mask ^ 0xffffffff;

		encrypted_words[0] = (otp_words[0] & bit_mask) ^ (otp_words[1] & inverse_mask);
		encrypted_words[1] = (otp_words[2] & bit_mask) ^ (otp_words[3] & inverse_mask);
		encrypted_words[2] = (otp_words[4] & bit_mask) ^ (otp_words[5] & inverse_mask);
		encrypted_words[3] = (otp_words[6] & bit_mask) ^ (otp_words[7] & inverse_mask);

		encrypted_words += 4;
		otp_words += 8;
	}
}

