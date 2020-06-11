#ifndef _ERR_
#define _ERR_

#ifdef __cplusplus
extern "C" {
#endif
/* Wypisuje informację o błędnym zakończeniu funkcji systemowej
i kończy działanie programu. */
extern void syserr(const char *fmt, ...);

/* Wypisuje informację o błędzie i kończy działanie programu. */
extern void fatal(const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif
