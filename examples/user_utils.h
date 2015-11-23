#ifndef USER_UTILS_H
#define USER_UTILS_H
#include <libnitro.h>

/*
 * Check the input string before converting it to an integer.
 * @param out	the destination, which will only be changed for a valid string
 * @param src	the source string that should represent an integer
 * @return	0 iff the input string is short enough and contains only digits
 */
int safe_atoi(int *out, const char *src);
/*
 * Fetch a string from the guest memory.
 * @param v_addr	the virtual address of the string
 * @param ram		the RAM file
 * @return		a copy of the string on success,
 *				which will need to be freed;
 *			NULL otherwise
 *				(so you can also pass it to free without error)
 */
char *copy_string(addr_t v_addr, struct ram_file *ram);

#endif /* USER_UTILS_H */
