#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/auxv.h>

int main() {
  printf("strace -p %d\n", getpid());
  printf("VDSO pointer: %p\n", getauxval(AT_SYSINFO_EHDR));
  char buf[1024];
  read(0, &buf, 1024);
  struct timeval t;
  if (gettimeofday(&t, NULL)) {
    perror("gettimeofday");
  }

  printf("%ld.%ld\n", t.tv_sec, t.tv_usec);
}
