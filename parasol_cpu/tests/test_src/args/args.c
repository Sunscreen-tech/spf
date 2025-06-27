typedef struct Foo {
    char a;
    short b;
    int c;
    long long d;
} Foo;


void fn1(char a, short b, int c, long long d, long long *output) {
    *output = a + b + c + d;
}

int fn2(char a, short b, int c, long long d) {
    return a + b + c + d;
}


int fn3(long long a, int b, short c, char d) {
    return a + b + c + d;
}

Foo fn4(long long a, int b, short c, char d) {
    Foo res = { d, c, b, a };

    return res;
}
