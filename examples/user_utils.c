#include <user_utils.h>

/* the maximum number of digits to read */
#define MAX_DIGITS	10
/* accept decimal numbers only */
#define BASE		10
/* the lowest decimal digit, corresponding to 0 */
#define LEAST_DIGIT	'0'

int safe_atoi(int *out, const char *src)
{
	int total = 0;
	unsigned char_i;

	for (char_i = 0; char_i < MAX_DIGITS; char_i++) {
		char current_char = src[char_i];
		int current_value;

		if (LEAST_DIGIT <= current_char &&
		    (current_value = (current_char - LEAST_DIGIT)) < BASE) {
			total = BASE * total + current_value;
		} else if (current_char == '\0') {
			*out = total;

			return 0;
		} else {
			return -1;
		}
	}

	return -1;
}
