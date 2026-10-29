/*
 * SnikrFlow test target 3 -- JNI-style export reaching a memory sink, via
 * an intermediate helper (so the path is 2 hops, not a direct call).
 *
 * NOTE: the exported function is only JNI-*named* (Java_com_example_Native_parse).
 * Its real signature here is (char *buf) so SnikrFlow's "symbolic buffer as
 * arg 1" model applies cleanly -- a real JNI function would start with
 * (JNIEnv *, jobject, ...), which SnikrFlow doesn't model yet.
 */
#include <string.h>

void copy_it(char *buf) {
    char local[16];
    strncpy(local, buf, 8);
}

void Java_com_example_Native_parse(char *buf) {
    copy_it(buf);
}

int main(void) {
    char buf[16] = {0};
    Java_com_example_Native_parse(buf);
    return 0;
}
