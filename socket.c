#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <sys/types.h>
#include <signal.h>
#include <linux/genetlink.h>
#include <pthread.h>
#include <syscall.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>

#define MAX_PAYLOAD 1024 /* maximum payload size*/
struct sockaddr_nl source, destination;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sfd;
struct msghdr msg;
volatile int done_flag;

void* pthread_callback()
{
    char *buffer;

    loop:
    // BLOCK READ HERE AND WAIT FOR MESSAGES IN LOOP, WILL ONLY EXIT WHEN KERNEL SENDS AN EMPTY STRING
    recvmsg(sfd, &msg, 0);
	
    buffer = (char*)NLMSG_DATA(nlh);
    printf("%s", buffer);
    if(buffer==NULL || strlen(buffer) == 0) {
        done_flag = 1;
    } else {
        goto loop;
    }

    // TODO close socket somewhere
    close(sfd);
    return NULL;
}
int create_socket(int socket_id)
{
    sfd = socket(PF_NETLINK, SOCK_RAW, 31);
    if (sfd < 0)
        return -1;

    memset(&source, 0, sizeof(source));
    source.nl_pid = socket_id;
    source.nl_family = AF_NETLINK;

    bind(sfd, (struct sockaddr *)&source, sizeof(source));

    memset(&destination, 0, sizeof(destination));
    destination.nl_family = AF_NETLINK;
    destination.nl_pid = 0;
    destination.nl_groups = 0;

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = socket_id;
    nlh->nlmsg_flags = 0;

    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&destination;
    msg.msg_namelen = sizeof(destination);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
	return 0;
}
