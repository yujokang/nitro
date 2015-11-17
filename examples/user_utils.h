#ifndef USER_UTILS_H
#define USER_UTILS_H

/*
 * Check the input string before converting it to an integer.
 * @param out	the destination, which will only be changed for a valid string
 * @param src	the source string that should represent an integer
 * @return	0 iff the input string is short enough and contains only digits
 */
int safe_atoi(int *out, const char *src);

#endif /* USER_UTILS_H */
