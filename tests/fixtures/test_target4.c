/*
 * SnikrFlow test target 4 -- path explosion.
 *
 * explode() loops over 32 input bytes with a data-dependent branch each
 * iteration (2^32 paths), and only calls sink_reached() if ALL of them
 * match. Any symbolic search needs well over a hundred basic-block steps
 * to leave the loop, so tiny step/state limits must stop it early and
 * report INCONCLUSIVE -- never "safe".
 */
void sink_reached(void) {
    volatile int marker = 1;
    (void)marker;
}

void explode(char *buf) {
    int matches = 0;
    for (int i = 0; i < 32; i++) {
        if (buf[i] == 'A') matches++;
    }
    if (matches == 32) sink_reached();
}

int main(void) {
    char buf[32] = {0};
    explode(buf);
    return 0;
}
