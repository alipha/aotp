#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


int usage(const char *prog_name);
int decrypt(FILE *otp_file, const char *otp_filename);
int decrypt_byte(const uint32_t *encrypted_words, const uint32_t *otp_words);


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

	error = decrypt(otp_file, argv[1]);
	fclose(otp_file);

	return error;
}


int usage(const char *prog_name) {
	fprintf(stderr, "Usage: %s OTP-FILE\n\n", prog_name);
	fprintf(stderr, "Decrypts the input from stdin using the provided OTP-FILE file.\n");
	fprintf(stderr, "The input to be decrypted must not be more than 1/256th the length of\n");
	fprintf(stderr, "the OTP-FILE file. The decrypted output will be written to stdout.\n\n");
	return 1;
}


int decrypt(FILE *otp_file, const char *otp_filename) {
	uint32_t encrypted_words[32];
	uint32_t otp_words[64];
	int plaintext_byte;

	while(fread(encrypted_words, sizeof encrypted_words, 1, stdin) == 1) {
		if(fread(otp_words, sizeof otp_words, 1, otp_file) != 1) {
			if(feof(otp_file)) {
				fprintf(stderr, "\n\"%s\" is not long enough to decrypt the input.\n\n", otp_filename);
				return 3;
			}

			fprintf(stderr, "\nError reading from \"%s\".\n\n", otp_filename);
			return 4;
		}

		plaintext_byte = decrypt_byte(encrypted_words, otp_words);

		if(plaintext_byte == -1) {
			fprintf(stderr, "\nError while attempting to decrypt input using \"%s\".\n", otp_filename);
			fprintf(stderr, "The input was not encrypted with the OTP file, or the input or OTP is corrupt.\n\n");
			return 7;
		}

		if(fputc(plaintext_byte, stdout) == EOF) {
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


int decrypt_byte(const uint32_t *encrypted_words, const uint32_t *otp_words) {
	uint32_t bit_mask;
	uint32_t inverse_mask;
	uint32_t word_0;
	uint32_t word_1;
	int nonzero_count = 0;
	int plaintext_byte = 0;

	for(int bit_pos = 0; bit_pos < 8; bit_pos++) {
		bit_mask = 0x55555555;
		inverse_mask = bit_mask ^ 0xffffffff;

		word_0 = encrypted_words[0] ^ (otp_words[0] & inverse_mask) ^ (otp_words[1] & bit_mask);
		word_0 |= encrypted_words[1] ^ (otp_words[2] & inverse_mask) ^ (otp_words[3] & bit_mask);
		word_0 |= encrypted_words[2] ^ (otp_words[4] & inverse_mask) ^ (otp_words[5] & bit_mask);
		word_0 |= encrypted_words[3] ^ (otp_words[6] & inverse_mask) ^ (otp_words[7] & bit_mask);

		word_1 = encrypted_words[0] ^ (otp_words[0] & bit_mask) ^ (otp_words[1] & inverse_mask);
		word_1 |= encrypted_words[1] ^ (otp_words[2] & bit_mask) ^ (otp_words[3] & inverse_mask);
		word_1 |= encrypted_words[2] ^ (otp_words[4] & bit_mask) ^ (otp_words[5] & inverse_mask);
		word_1 |= encrypted_words[3] ^ (otp_words[6] & bit_mask) ^ (otp_words[7] & inverse_mask);

		/* TODO: this is probably not time-constant and I'm not sure how to make it be. */
		nonzero_count += (word_0 != 0) + (word_1 != 0);

		if(word_1 == 0)
			plaintext_byte |= (1 << bit_pos);

		encrypted_words += 4;
		otp_words += 8;
	}

	if(nonzero_count != 8)
		return -1;

	return plaintext_byte;
}

