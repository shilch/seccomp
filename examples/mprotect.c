#include <sys/mman.h>

const char string[] = "Beispiel mit mprotect(2)";

// https://stackoverflow.com/a/3407254/6338257
size_t round_up_to_multiple_of(size_t x, int m) {
    if (m == 0)
        return x;

    int r = x % m;
    if (r == 0)
        return x;

    return x + m - r;
}

int main() {
    int pagesize = 4096;
    void* addr = (void*)(((size_t)string) % ((size_t)pagesize));
    size_t len = round_up_to_multiple_of(sizeof(string), pagesize);

    mprotect(addr, len, PROT_READ);
    mprotect(addr, len, PROT_READ|PROT_WRITE);
}