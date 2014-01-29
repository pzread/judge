#ifndef DEF_H
#define DEF_H

#define container_of(ptr,type,member) ({    \
	const __typeof__(((type *)0)->member) *__mptr = (ptr);  \
	(type *)((char *)__mptr - offsetof(type,member));})

#define max(a,b) ({__typeof__(a) _a = (a);  \
	__typeof__(b) _b = (b);	\
	_a > _b ? _a : _b;})
#define min(a,b) ({__typeof__(a) _a = (a);  \
	__typeof__(b) _b = (b);	\
	_a < _b ? _a : _b;})

#define STATUS_NONE 0
#define STATUS_AC 1
#define STATUS_WA 2
#define STATUS_RE 3
#define STATUS_TLE 4
#define STATUS_MLE 5
#define STATUS_CE 6
#define STATUS_ERR 7

#endif
