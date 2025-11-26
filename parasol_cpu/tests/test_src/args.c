typedef struct Foo {
    char a;
    short b;
    int c;
    long long d;
    __int128 e;
} Foo;

void fn1(char a, short b, int c, long long d, __int128 e, long long *output) {
    *output = a + b + c + d + e;
}

int fn2(char a, short b, int c, long long d, __int128 e) {
    return a + b + c + d + e;
}


int fn3(__int128 e, long long a, int b, short c, char d) {
    return a + b + c + d + e;
}

Foo fn4(__int128 a, long long b, int c, short d, char e) {
    Foo res = { e, d, c, b, a };

    return res;
}
