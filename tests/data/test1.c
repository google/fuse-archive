#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <archive.h>

// gcc -o test1 -Wall test1.c -larchive && ./test1
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
  r = archive_read_append_filter_program(a, "base64 -d");
  printf("<<< archive_read_append_filter_program() returned %d\n\n", r);
  assert(r == ARCHIVE_OK);

  printf(">>> archive_read_support_format_raw()\n");
  r = archive_read_support_format_raw(a);
  printf("<<< archive_read_support_format_raw() returned %d\n\n", r);
  assert(r == ARCHIVE_OK);

  const char* const filename = "hi.txt.b64.b64";
  printf(">>> archive_read_open_filename()\n\n");
  r = archive_read_open_filename(a, filename, 16*1024);
  
  printf("<<< archive_read_open_filename() returned %d\n\n", r);
  assert(r == ARCHIVE_OK);

  printf(">>> archive_read_free()\n");
  r = archive_read_free(a);
  printf("<<< archive_read_free() returned %d\n\n", r);
  assert(r == ARCHIVE_OK);

  printf("Done\n");
}
