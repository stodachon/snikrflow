/*
 * SnikrFlow test target 5 -- unresolved indirect call.
 *
 * main() hands sink_reached to run_callback(), which calls it through a
 * function-pointer PARAMETER. At runtime sink_reached definitely runs,
 * but a function-level call graph has no edge main -> sink_reached (the
 * target is only known at the call site). This is the documented
 * limitation behind "not reachable is NOT proof of safety" -- see
 * tests/test_reachability.py.
 */
void sink_reached(void) { volatile int m = 1; (void)m; }

void run_callback(void (*cb)(void)) {
    cb();
}

int main(void) {
    run_callback(sink_reached);
    return 0;
}
