// Adaptiert von https://openbook.rheinwerk-verlag.de/c_von_a_bis_z/025_c_netzwerkprogrammierung_006.htm
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>

#define PORT 1234
#define RCVBUFSIZE 1024

static void echo( int );
static void error_exit(const char *errorMessage);

static void echo(int client_socket) {
    char echo_buffer[RCVBUFSIZE];
    int recv_size;
    time_t zeit;

    if((recv_size =
            recv(client_socket, echo_buffer, RCVBUFSIZE,0)) < 0)
        error_exit("Fehler bei recv()");
    echo_buffer[recv_size] = '\0';
    time(&zeit);
    printf("Nachrichten vom Client : %s \t%s",
            echo_buffer, ctime(&zeit));
}

static void error_exit(const char *error_message) {
    fprintf(stderr, "%s: %s\n", error_message, strerror(errno));
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    struct sockaddr_in server, client;
    int sock, fd;
    unsigned int len;

    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0)
        error_exit("Fehler beim Anlegen eines Sockets");

    memset( &server, 0, sizeof (server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(PORT);

    if(bind(sock,(struct sockaddr*)&server, sizeof( server)) < 0)
        error_exit("Kann das Socket nicht \"binden\"");

    if(listen(sock, 5) == -1 )
         error_exit("Fehler bei listen");

    printf("Server bereit - wartet auf Anfragen ...\n");
    for (;;) {
        len = sizeof(client);
        fd = accept(sock, (struct sockaddr*)&client, &len);
        if (fd < 0)
            error_exit("Fehler bei accept");
        printf("Bearbeite den Client mit der Adresse: %s\n",
           inet_ntoa(client.sin_addr));
        echo( fd );
        close(fd);
    }
    return EXIT_SUCCESS;
}
