#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    printf "Benutzung: $0 Binärdatei\n" >&2
    exit 1
fi

SYSCALL_REGEX="$(jq -r 'to_entries | .[].key' model.json | awk '
    { syscalls[$0] }
    END {
        printf("(")
        i = 0
        for (key in syscalls) {
            if (i != 0) {
                printf("|")
            }
            printf("%s", key)
            i++
        }
        printf(")")
    }
')"

objdump -d "$1" |
    egrep "callq.+<$SYSCALL_REGEX@plt>" |
    sed -E 's ^\s*([0-9a-f]+).*<([a-z]+)@plt>\s*$ \2\t0x\1 ' |
    sort |
    awk '
    BEGIN {
        scidx = 0
        printf("{")
    }
    $1 != prev {
        prev = $1
        addridx = 0

        if (scidx) {
            printf("],\n")
        }
        scidx++

        printf("\"%s\": [", $1)
    }
    {
        if (addridx) {
            printf(", ")
        }
        printf("%s", 0 + $2)
        addridx++
    }
    END {
        printf("]}")
    }
    ' |
    jq .