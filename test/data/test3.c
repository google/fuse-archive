#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <archive.h>

// gcc -o test3 -Wall test3.c -larchive && ./test3
int main() {
  printf(">>> archive_read_new()\n");
  struct archive* const a = archive_read_new();
  printf("<<< archive_read_new() returned %p\n\n", a);
  assert(a != NULL);

  int r;
  printf(">>> archive_read_append_filter_program()\n");
  r = archive_read_append_filter_program(a, "base64 -d");
  printf("<<< archive_read_append_filter_program() returned %d\n\n", r);
  assert(r == ARCHIVE_OK);
  
  printf(">>> archive_read_append_filter_program()\n");
  r = archive_read_append_filter_program(a, "brotli -d");
  printf("<<< archive_read_append_filter_program() returned %d\n\n", r);
  assert(r == ARCHIVE_OK);

  printf(">>> archive_read_support_format_raw()\n");
  r = archive_read_support_format_raw(a);
  printf("<<< archive_read_support_format_raw() returned %d\n\n", r);
  assert(r == ARCHIVE_OK);

  const char* const data = "IUgABENhbiB5b3UgcmVhZCB0aGF0PwoD";
  printf(">>> archive_read_open_memory()\n");
  r = archive_read_open_memory(a, data, strlen(data));
  printf("<<< archive_read_open_memory() returned %d\n\n", r);
  assert(r == ARCHIVE_OK);

  printf(">>> archive_read_free()\n");
  r = archive_read_free(a);
  printf("<<< archive_read_free() returned %d\n\n", r);
  assert(r == ARCHIVE_OK);

  printf("Done\n");
}
