---
title: "minimal HTTP server in C"
date: 2024-05-13
categories: [IT Networking] 
tags: [Low Level Coding, Network Security]
---

# minimal HTTP server in C

A *socket* is one endpoint of a two-way communication link between two programs running on the network. A socket is bound to a port number so that the TCP layer can identify the application that data is destined to be sent to.

![Untitled](minimal HTTP server in C/Untitled.png)

## Writing the Server

1. Create the server address that the socket is going to be binded to
2. Creating the socket
3. Binding it to an the created address(IP and a port)
4. Listening for incomming connections
5. Accepting connections
6. Handling Requests and sending Responses

## Prequesities :

- basic understanding of networking
- C programming language
- Input/Output system calls in C (best ressource [https://www.geeksforgeeks.org/input-output-system-calls-c-create-open-close-read-write/?ref=lbp](https://www.geeksforgeeks.org/input-output-system-calls-c-create-open-close-read-write/?ref=lbp))

## Let’s make a simple HTTP server handling GET requests

### Headers Needed :

<sys/socket.h> : this header includes functions, types, constants used for socket programming, for example : socket(),bind(),connect(),accept(),recvfrom(),sendto()…..

<netinet/in.h> : this header includes definitions for internet protocol(IP) structures and constants, for example it defines the struct sockaddr_in structure used to define the socket address internet. it also defines AF_INET which represents the family for IPV4 internet addresses

### sockaddr_in structure :

in order to create a socket you have to create what represents it’s body, we are going to later on bind the socket to this body; socket is defined by the socket internet family, the socket internet port, the socket internet address.

This is done via a struct holding the socket members :

```c
struct sockaddr_in {	
	sa_family_t sin_family,
	in_port_t sin_port,
	struct in_addr sin_addr,
	char zero[8] //used for data padding and memory alignement
}
```

Structure’s memebers Datatypes:

sa_family : an unsigned integer that holds the socket address ( it is usually AF_INET)

in_port_t : an unsigned short integer that holds the socket port in network byte order

in_addr  : a structure that holds the sin_addr in network byte order

```c
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h> // contains the inet_ntoa() function

int main(){
	
	struct sockaddr_in server_address;
	
	server_address.sin_family = AF_INET; 
	server_address.sin_port = htons(8080); /* "host to network short" transforms from int 
	to network byte order */
	server_address.sin_addr.s_addr = inet_addr("192.168.1.100") /* transforms the IP address 
	string to it's binary representation respecting the convention of the network byte order*/
	
	//alternative to the previous line we can use 
	server_addr.sin_addr.s_addr = INADDR_ANY; /*sets the socket address to any available IP 
	address */
	
	/*if we print the structure's fields using %d data formatter we are likely
	to get meaningless information because all of these fields are in 
	netword byte order, therefore we should use some functions in order */
	
	printf("%d\n",server_address.sin_family);
	printf("%d\n",ntohs(server_address.sin_port)); /* "network to host" transforms network
	byte order to integer*/ 
	printf("%s\n",inet_ntoa(server_address.sin_addr)); /* "network to ASCII" transforms the 
	binary representation of the IP address to ASCII*/
	
	//to be continued
	
	return 0;
}
```

<aside>
💡 You are probably asking what does the network byte order mean :

The network byte order or the big-endian convention is a standardised method of representing different byte datatypes when transmitted over the network, in the network byte order, the most significant byte(the byte with the highest value) is is placed first, followed by less significant byte.

Example:

the most significant byte of 300 is 0x1 and the less significant byte is 0x2C 

</aside>

### Socket creation and  binding the socket to the server address and Setting the socket on listening state for incoming connections

we create the socket and bind the server address to this socket, to allow the server to listen on incoming connections to a specific IP and port.

to fulfil such task we use the socket(), bind() and listen() functions.

socket() :

```c
int socket(int domain,int type,int protocol)
```

domain : specifies the protocol family used for the communcation (AF_INET, AF_INET6….)

type : specifies the communcation semantics(SOCK_STREAM, SOCK_DGRAM…)

protocol : the protocol supporting a protocol type within a socket family, use 0 for default protocol.

return value : the file descriptor of the socket

bind():

```c
int bind(int socketfd,struct sockaddr *server_address,socklen_t server_address_len)
```

socketfd : the socket’s file descriptor

server_address : pointer to the structure of the server address casted to the generic socket address “struct sockaddr”

server_address_len: the length of the server_address structure

listen():

```c
int listen(int socketfd,int backlog)
```

socketfd: the socket file descriptor

backlog: the maximum value of queue’s pending incoming connections waiting to be accepted

Action:

```c
int main(){
	
	// Continuity
	int sockaddr_in_len = sizeof(server_address)
	int socketfd;
	if( (socketfd = socket(AF_INET,SOCK_STREAM,0))<0){
		perror("failed to create a socket");
		return -1;
	}

	if( bind(socketfd,(struct sockaddr *)&server_address,sockaddr_in_len) <0){
		perror("failed to bind to the socket to the server address");
		return -1;
	}
	
	if(listen(socketfd,5)<0){
		perror("failed to listen on incoming connections");
		return 0;
	}
	
	printf("listening on port %d",ntohs(server_address.sin_port))
	//to be continued
	
	return 0;
}
```

### Accept incoming connections, Read incoming data and send response to the client and close the connection.

to fulfil such task we use the following functions : accept(), read(), write(), close()

 

accept():

```c
int accept(int socketfd,struct sockaddr *client_address,socklen_t *client_address_len)
```

socketfd: the file descriptor of the server address

sockaddr: a pointer to the client socket address

client_address_len:  a pointer to the length of the client’s socket address

read():

```c
int read(int client_socket_fd,void *buffer,size_t count)
```

client_socket_fd : the file descriptor of the client address

buffer: pointer to a buffer in which we read and save the incoming data

count: the number of bytes of incoming data to save to the buffer

the return value is the number of bytes that were successfully read

write():

```c
int write(int client_socket_fd,void *buffer,size_t bytes)
```

client_socket_fd : the file descriptor of the client address

buffer: a pointer to the response data that is going to be communicated to the client

bytes: the number of bytes that were successfully communicated to the client

close():

```c
close(int client_sock_fd)
```

client_socket_fd : the file descriptor of the client address

Action:

```c
int main(){

	//continuity
	
	struct sockaddr_in client_address;
	socklen_t client_address_len = sizeof(client_address);
	
	char *buffer = (char*)calloc(1024*sizeof(char));
	char *response = "HTTP/1.1 200 OK\nContent-Type:text/html\n\nHello World;"
	int client_socket;
	
	while(1){
		if((client_socket=accept(socketfd,(struct sockaddr *)&client_address,&client_address_len))<0){
			perror("accept");
			continue;	
		}
	
		read(client_socket,buffer,sizeof(buffer);
		printf("Received request : %s\n",buffer);
		
		write(client_socket,response,strlen(response));
	
		close(client_socket);
	}

	return 0;
}
```

## Putting all things together:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 4444

int main(){

    struct sockaddr_in server_address;
    int server_socketfd;

    if((server_socketfd=socket(AF_INET,SOCK_STREAM,0))<0){
        perror("failed to create the server socket");
        exit(1);
    }

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr =  INADDR_ANY;

    printf("server ip addr = %s\n",inet_ntoa(server_address.sin_addr));
    printf("server port = %d\n",ntohs(server_address.sin_port));
    printf("server socket fd = %d\n",server_socketfd);

    if(bind(server_socketfd,(struct sockaddr *)&server_address,sizeof(server_address))<0){
        perror("failed to bind the socket to the server address");
        exit(1);
    }

    if(listen(server_socketfd,5)<0){
        perror("failed to listen for incoming connections");
        exit(1);
    }

    printf("listening on port %d\n",PORT);

    struct sockaddr_in client_addresse;
    socklen_t client_addr_len = sizeof(client_addresse);
    int client_socketfd;

    char *buffer = (char*)calloc(1024,sizeof(char));
    char *response = "HTTP/1.1 200 OK\nContent-Type:text/html\n\nHello World;\n";

    while(1){

        if((client_socketfd=accept(server_socketfd,(struct sockaddr*)&client_addresse,&client_addr_len))<0){
            printf("Accept");
            continue;
        }
 
        read(client_socketfd,buffer,sizeof(buffer));
        /*to read the whole buffer put 1024 instead of the sizeof(buffer) because
        it reads the size of the pointer not the actual size of the allocated 
        memory */
        printf("Received request: %s\n",buffer);

        write(client_socketfd,response,strlen(response));

        close(client_socketfd);
    }
    
    //it doesnt reach this section of the code
    free(buffer); 
    close(server_socketfd);
    return 0;
}
```

<aside>
💡 to check the server’s connectivity visit or curl [https://localhost](https://localhost):4444/

</aside>

### there is small problem in the previous code

Terminal:

![Untitled](minimal HTTP server in C/Untitled%201.png)

since we are using a while(1) loop we are never going to get out of the loop only by interrupting the programm with Ctrl+C, and when you try o rerun the program the port is going to be still in use, because the socket is left in the TIME_WAIT, in which the operating system ensures that any lingering packets related to the socket are fully processed, it only stays for a short period of time.

all of this because closing the server_socketfd wasnt reached, same thing for the free() function which causes memory leaks.

### Solutions:

Solution1:

I refere you to read a bit about signals in C ([https://www.geeksforgeeks.org/signals-c-language/](https://www.geeksforgeeks.org/signals-c-language/))

Define a signal handler for handling the SIGINT signal, and registring that handler for SIGINT, the signal handler is going to include operations that closes the server_socketfd alongside with freeing the allocated memory

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#define PORT 4444

int server_socketfd;
char *buffer;

void handle_signal(int sig){
    printf("Caught signal %d\n",sig);
    close(server_socketfd);
    free(buffer);
    printf("server socket fd is closed successfully\n");
    printf("the buffer's allocated memory is freed\n");
    exit(sig);
}

int main(){

    struct sockaddr_in server_address;

    if((server_socketfd=socket(AF_INET,SOCK_STREAM,0))<0){
        perror("failed to create the server socket");
        exit(1);
    }

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr =  INADDR_ANY;

    printf("server ip addr = %s\n",inet_ntoa(server_address.sin_addr));
    printf("server port = %d\n",ntohs(server_address.sin_port));
    printf("server socket fd = %d\n",server_socketfd);

    if(bind(server_socketfd,(struct sockaddr *)&server_address,sizeof(server_address))<0){
        perror("failed to bind the socket to the server address");
        exit(1);
    }

    if(listen(server_socketfd,5)<0){
        perror("failed to listen for incoming connections");
        exit(1);
    }

    printf("listening on port %d\n",PORT);

    struct sockaddr_in client_addresse;
    socklen_t client_addr_len = sizeof(client_addresse);
    int client_socketfd;

    buffer = (char*)calloc(1024,sizeof(char));
    char *response = "HTTP/1.1 200 OK\nContent-Type:text/html\n\nHello World;\n";

    signal(SIGINT,handle_signal);

    while(1){

        if((client_socketfd=accept(server_socketfd,(struct sockaddr*)&client_addresse,&client_addr_len))<0){
            printf("Accept");
            continue;
        }
 
        read(client_socketfd,buffer,sizeof(buffer));
        /*to read the whole buffer put 1024 instead of the sizeof(buffer) because
        it reads the size of the pointer not the actual size of the allocated 
        memory */
        printf("Received request: %s\n",buffer);

        write(client_socketfd,response,strlen(response));

        close(client_socketfd);
    }
    
    return 0;
}
```

Terminal 1:

![Untitled](minimal HTTP server in C/Untitled%202.png)

Terminal 2:

![Untitled](minimal HTTP server in C/Untitled%203.png)

Terminal1

![Untitled](minimal HTTP server in C/Untitled%204.png)

Solution2:

we use the setsockopt() function

```c
int setsockopt(int socketfd,int level,int option_name, const void *option_value,socklen_t sizeof_option_value)
```

socktfd: socket file descriptor to which you want to set options

level: the protocol level in which the option resides for example a protocol level for sockets is SOL_SOCKET.

option_name : the name of the option in the protocol level

operation_value: pointer to a value of the option (usualy a boolean that either enable or disable the option)

sizeof_option: size of the option value

on success it returns 0 on failure it returns -1

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 4444

int main(){

    struct sockaddr_in server_address;
    int server_socketfd;

    const int opt = 1;

    if((server_socketfd=socket(AF_INET,SOCK_STREAM,0))<0){
        perror("failed to create the server socket");
        exit(1);
    }

    if(setsockopt(server_socketfd,SOL_SOCKET,SO_REUSEADDR | SO_REUSEPORT ,&opt,sizeof(opt))<0){
        perror("failed to set options to the socket");
        exit(1);
    }

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    //server_address.sin_addr.s_addr =  INADDR_ANY;
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1");

    printf("server ip addr = %s\n",inet_ntoa(server_address.sin_addr));
    printf("server port = %d\n",ntohs(server_address.sin_port));
    printf("server socket fd = %d\n",server_socketfd);

    if(bind(server_socketfd,(struct sockaddr *)&server_address,sizeof(server_address))<0){
        perror("failed to bind the socket to the server address");
        exit(1);
    }

    if(listen(server_socketfd,5)<0){
        perror("failed to listen for incoming connections");
        exit(1);
    }

    printf("listening on port %d\n",PORT);

    struct sockaddr_in client_addresse;
    socklen_t client_addr_len = sizeof(client_addresse);
    int client_socketfd;

    char *buffer = (char*)calloc(1024,sizeof(char));
    char *response = "HTTP/1.1 200 OK\nContent-Type:text/html\n\nHello World;\n";

    while(1){

        if((client_socketfd=accept(server_socketfd,(struct sockaddr*)&client_addresse,&client_addr_len))<0){
            printf("Accept");
            continue;
        }
 
        read(client_socketfd,buffer,1024);
        printf("Received request: %s\n",buffer);

        //send(client_socketfd,response,strlen(response),0);
        write(client_socketfd,response,strlen(response));
        
        close(client_socketfd);
    }
    
    
    return 0;
}
```

Terminal:

![Untitled](minimal HTTP server in C/Untitled%205.png)

![Untitled](minimal HTTP server in C/Untitled%206.png)

## Lets write a simple client that connects to the server:

![Untitled](minimal HTTP server in C/Untitled%207.png)

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#define PORT 4444

int main(){

    int client_socketfd;
    struct sockaddr_in server_address;
    
    if((client_socketfd=socket(AF_INET,SOCK_STREAM,0))<0){
        perror("failed to create the client's socket");
        exit(1);
    }

    server_address.sin_family=AF_INET;
    server_address.sin_port=htons(PORT);
    server_address.sin_addr.s_addr=inet_addr("127.0.0.1");

    if(connect(client_socketfd,(struct sockaddr *)&server_address,sizeof(server_address))<0){
        perror("failed to connect to the server's socket");
        exit(1);
    }

    char *buffer = (char *)calloc(1024,sizeof(char));
    char *hello = "Hello from Client";
    
    write(client_socketfd,hello,strlen(hello));
    //send(client_socketfd,hello,strlen(hello),0);
    printf("message '%s' is sent to the server\n",hello);

    read(client_socketfd,buffer,1024);
 

    printf("message received from the server : %s\n",buffer);

    close(client_socketfd);
    free(buffer);
    return 0;
}
```

Client’s Terminal:

![Untitled](minimal HTTP server in C/Untitled%208.png)

Server’s Terminal:

![Untitled](minimal HTTP server in C/Untitled%209.png)