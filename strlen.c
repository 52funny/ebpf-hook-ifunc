#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
  int len = strlen(argv[argc - 1]);
  printf("len: %d\n", len);
  return 0;
}

