/*
 * SnikrFlow test target -- deliberately trivial, for validating the
 * `solve` command's symbolic execution engine in isolation from real
 * crackme complexity (anti-tampering, heavy branching, etc).
 *
 * check_password() takes a buffer as its first argument (matches
 * SnikrFlow's `solve` assumption: symbolic buffer -> arg 1) and calls
 * sink_reached() only if the first 4 bytes spell "Snik".
 *
 * Usage:
 *   snikrflow functions test_target        (find the two addresses below)
 *   snikrflow solve test_target --source <check_password addr> --target <sink_reached addr>
 *   Expect: SAT, candidate input starting with 53 6e 69 6b ("Snik...")
 */

void sink_reached(void) {
    volatile int marker = 1;
    (void)marker;
}

void check_password(char *buf) {
    if (buf[0] == 'S' && buf[1] == 'n' && buf[2] == 'i' && buf[3] == 'k') {
        sink_reached();
    }
}

int main(void) {
    char buf[8] = {0};
    check_password(buf);
    return 0;
}
