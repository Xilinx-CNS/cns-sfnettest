#ifndef __NETTEST_GCC_H__
#define __NETTEST_GCC_H__


#ifdef __x86_64__
static inline void sfnt_tsc(uint64_t* pval) {
  uint64_t low, high;
  __asm__ __volatile__("rdtsc" : "=a" (low) , "=d" (high));             
  *pval = (high << 32) | low;
}
#elif defined(__i386__)
# define sfnt_tsc(pval)  __asm__ __volatile__("rdtsc" : "=A" (*(pval)))
#else
# error Unknown processor.
#endif


#endif  /* __NETTEST_GCC_H__ */
