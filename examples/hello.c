#include <unistd.h>

const char string[] = "Hallo, Welt!\n";

int main() {
    write(1, string, sizeof(string));
    return 0;
}
