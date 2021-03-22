#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static const char prefixes[] = "badakzfictc";
static const size_t prefix_lengths[] = {0, 2, 2, 1, 1, 2, 1, 2};

static void simple_execve(char* path) {
    printf("Executing shell %s\n", path);
    char* const argv[] = {path, NULL};
    execve(path, argv, NULL);
    perror("failed to exec shell");
}

static char* make_shell_string(int index) {
    size_t prefix_length = prefix_lengths[index];
    size_t offset = 0;
    for(int i = 0; i < index; i++) {
        offset += prefix_lengths[i];
    }

    size_t total_length = 5 + 2 + prefix_length;
    char* final_string = (char*) malloc(total_length + 1);

    memcpy(final_string, "/bin/", 5);
    memcpy(&final_string[5], &prefixes[offset], prefix_length);
    memcpy(&final_string[5 + prefix_length], "sh", 2);
    return final_string;
}

static void execute_shell(int index) {
    char* shell_path = make_shell_string(index);
    simple_execve(shell_path);
    free(shell_path); // Only executed in case of error
}

static int pick_random_shell() {
    return rand() % (sizeof(prefix_lengths) / sizeof(size_t));
}

int main(int argc, char** argv) {
    int index = pick_random_shell();
    execute_shell(index);
}
