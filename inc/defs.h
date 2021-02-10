#ifndef DENS_DEFS_H
#define DENS_DEFS_H

#if defined (__GNUC__) || defined(__clang__)
# define NORETURN __attribute__((noreturn))
# define PACKED __attribute__((__packed__))
#elif defined(_MSC_VER)
# define NORETURN __declspec(noreturn)
#else
# define NORETURN
# define PACKED
#endif

#endif
