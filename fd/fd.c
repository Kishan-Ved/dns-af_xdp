#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>      // control open file descriptors
#include <sys/socket.h>

int main(int argc, char* argv[])
{
    int ifd, ofd, pipefd[2], sockfd;

    printf("Descriptor\tPointer\t\tDescription\n");
    printf("-----------------------------------------\n");
    printf("%d\t\t%p \tTerminal's Input Device\n", STDIN_FILENO, stdin);
    printf("%d\t\t%p \tTerminal's Outut Device\n", STDOUT_FILENO, stdout);
    printf("%d\t\t%p \tTerminal's Error Device\n", STDERR_FILENO, stderr);

    ifd = open("input.txt", O_RDONLY);
    ofd = open("output.txt", O_WRONLY);
    printf("%d\t\t%p \tinput.txt\n", ifd, fdopen(ifd, "r"));
    printf("%d\t\t%p \toutput.txt\n", ofd, fdopen(ofd, "w"));
    pipe(pipefd);
    printf("%d\t\t%p \tPipe Read End\n", pipefd[0], fdopen(pipefd[0], "r"));
    printf("%d\t\t%p \tPipe Write End\n", pipefd[1], fdopen(pipefd[1], "w"));

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    printf("%d\t\t%p \tSocket\n", sockfd, fdopen(sockfd, "r+"));

    /***
    int sendmsg(int s, const struct msghdr *msg, int flags);

    struct msghdr {
        void         * msg_name;     // optional address
        socklen_t    msg_namelen;    // size of address
        struct iovec * msg_iov;      // scatter/gather array
        size_t       msg_iovlen;     // # elements in msg_iov
        void         * msg_control;  // ancillary data, see below
        socklen_t    msg_controllen; // ancillary data buffer len
        int          msg_flags;      // flags on received message
    };

    ***/

    ssize_t n = send(sockfd, "Hello, World!", 14, 0);
    printf("Sent %ld bytes\n", n);

    return 0;
}