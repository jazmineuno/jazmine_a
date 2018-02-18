#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define MAX_MESSAGE 8192

char *socket_path = "/tmp/jazmine_a.sock";

int main(int argc, char *argv[]) {
  struct sockaddr_un addr;
  char buf[MAX_MESSAGE];
  int fd,rc;

  if (argc > 1) socket_path=argv[1];

printf("\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\njazcli jazmine_a UNIX domain socket client\nCopyright 2018 Waitman Gobble <waitman@tradetal.com>\nsocket: %s\n\nType 'exit' to quit.\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n",socket_path);

  if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    perror("socket error");
    exit(-1);
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  if (*socket_path == '\0') {
    *addr.sun_path = '\0';
    strncpy(addr.sun_path+1, socket_path+1, sizeof(addr.sun_path)-2);
  } else {
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);
  }

  if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
    perror("connect error");
    exit(-1);
  }

        if( recv(fd , buf , sizeof(buf) , 0) < 0)
    {
        puts("recv failed");
    }
        printf("%s",buf);


  while( (rc=read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
	if (strncmp(buf,"exit",4)==0)
	{
		close(fd);
		exit(EXIT_SUCCESS);
	}
    if (write(fd, buf, rc) != rc) {
      if (rc > 0) fprintf(stderr,"partial write");
      else {
        perror("write error");
        exit(-1);
      }
    }

memset(&buf[0], 0, sizeof(buf));	
	        if( recv(fd , buf , sizeof(buf) , 0) < 0)
    {
        puts("recv failed");
    }
        printf("%s",buf);
memset(&buf[0], 0, sizeof(buf));

  }

  return 0;
}

