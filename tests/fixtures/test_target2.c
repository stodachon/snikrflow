/*
 * SnikrFlow test target 2 -- validates data-flow (not just control-flow)
 * taint detection. Unlike test_target.c (which only branches based on
 * the input), this one passes the tainted buffer POINTER directly into
 * a sink function as its argument -- the scenario `dataflow` is meant
 * to catch.
 *
 * Usage:
 *   snikrflow functions test_target2   (or objdump) to confirm addresses
 *   snikrflow dataflow test_target2 --source <relay addr> --sink <strlen@plt addr>
 *   Expect: POSSIBLE (tainted via pointer dereference on arg 1)
 */

#include <string.h>

void relay(char *buf) {
    size_t len = strlen(buf);   // sink: buf pointer (tainted memory) passed directly as arg 1
    (void)len;
}

int main(void) {
    char buf[8] = {0};
    relay(buf);
    return 0;
}
