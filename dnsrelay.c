#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <WinSock2.h>
#include <Windows.h>
#include <time.h>
#pragma comment(lib, "WS2_32.lib")

#define PORT 53
#define BUFFER_SIZE 1024
const char* LOCAL_IP = "127.0.0.1";
const char* SERVER_IP = "192.168.124.1";
const char* LOCAL_FILE = "dnsrelay.txt";

typedef struct DNSHEADER {
	unsigned short ID;
	unsigned short Flag;
	unsigned short Qdcount;
	unsigned short Ancount;
	unsigned short Nscount;
	unsigned short Arcount;
}DNSHEADER;			//dns头

typedef struct DNSQUESTION {
	unsigned short Qtype;
	unsigned short Qclass;
}DNSQUESTION;		//dns问题

typedef struct DNSRESOURCE {
	unsigned short Type;
	unsigned short Class;
	unsigned int TTL;
	unsigned short Length;
}DNSRESOURCE;		//dns答案（上面三个结构体用到的不多，写出来方便查看结构）

typedef struct Node {
	char IP[20];
	char DN[80];
	struct Node* next;
}Node;					//链表储存文件中IP和DomainName

Node* HEAD;											//全局变量，文件信息的链表头

/*
*读取文件，并返回链表头的节点,同时输出文件中保存的信息
*参数file为需要读取的文件的路径，level表示调试等级
*/
Node* OpenFileT(char* file, int level) {

	int flag = 0;						//用于标记当属于IP还是域名
	FILE* f;
	if ((f = fopen(file, "r")) == NULL) {
		perror("Can't open the file");
		exit(1);
	}
	char temp[BUFFER_SIZE];				//储存每一行的字符串
	Node* head = (Node*)malloc(sizeof(Node));
	head->next = NULL;
	Node* p = head;
	int n = 0;
	while (!feof(f)) {
		fgets(temp, BUFFER_SIZE, f);
		for (int i = 0, fl = 0, iplength = 0; i < BUFFER_SIZE; i++) {
			/*IP*/
			if (fl == 0) {
				if (temp[i] != ' ') {
					p->IP[i] = temp[i];
				}
				/*为空格时，IP范围结束*/
				else {
					iplength = i;
					fl = 1;
					p->IP[i] = '\0';
				}
			}
			/*域名*/
			else if (fl == 1) {
				if (temp[i] != '\n') {
					p->DN[i - iplength - 1] = temp[i];
				}
				/*为换行时，域名范围结束*/
				else {
					p->DN[i - iplength - 1] = '\0';
					break;
				}
			}
		}
		p->next = (Node*)malloc(sizeof(Node));
		p = p->next;
		p->next = NULL;
		n++;
	}
	/*调试等级为2时才输出文件信息*/
	if (level == 2) {
		printf("\n读取文件信息如下：\n");
		for (Node* p = head; p; p = p->next) {
			printf("\t%s  ", p->DN);
			printf("%s\n ", p->IP);
		}
		printf("文件读取完毕,共%d条信息\n", n);
	}
	return head;
}

/*
*读取链表，返回查询域名的结果，包含域名则返回1，否则返回0
*domainName为需要读取的域名，ip为域名对应的IP地址，查找到的话就将结果填入到ip数组中，head为链表头
*/
int LookUp(char* domainName, char* ip, Node* head) {
	Node* p = head;
	int flag = 0;
	while (p) {
		if (strcmp(domainName, p->DN) == 0) {
			flag = 1;
			char* t1 = p->IP;
			char* t2 = p->IP;
			int i = 0;
			/*通过t1，t2两个指针进行读取，当读到'.'时，说明当前数字结束*/
			while (*t1 != '\0') {
				if (*t1 == '.') {
					*t1 = '\0';
					ip[i] = (char)atoi(t2);
					i++;
					t2 = t1 + 1;
				}
				t1++;
			}
			/*字符串转数字*/
			ip[i] = (char)atoi(t2);
			return flag;
		}
		p = p->next;
	}
	return flag;
}

/*
*输出域名时使用
*/
void PrintName(char* buf) {
	char* p = buf;
	while (*p != 0) {
		if (*p >= 33) {
			printf("%c", *p);
		}
		else {
			printf(".");
		}
		p++;
	}
}

/*
*输出以buf为头的响应包中，从from开始表示的CNAME
*/
void PrintNameTemp(char* buf, char* from) {
	char* p = from;
	while (*p != 0) {
		/*当前位为0xC0时，表示下一位为指针，指向buf+下一位数字的位置*/
		if (*p == (char)192) {
			PrintNameTemp(buf, buf + *((unsigned char*)p + 1));
			return;
		}
		else if (*p >= 33)
			printf("%c", *p);
		/*小于33的以'.'进行输出*/
		else {
			printf(".");
		}
		p++;
	}
	return;
}

/*
*输出以buf为头的域名
*/
void DomainName(char* buf)
{
	printf("[DomainName = ");
	PrintName(buf);
	printf("]\t");
}

/*
*输出以buf为头的域名
*同时会将数值小于33的字符改成'.'，便于在LookUp()函数中进行比较
*/
void ToDomainName(char* buf) {
	char* p = buf;
	while (*p != 0) {
		if (*p >= 33) {
			if (*p >= 'A' && *p <= 'Z')
				*p = *p + 32;
			//			printf("%c", *p);
		}
		else {
			*p = '.';
			//			printf(".");
		}
		p++;
	}
}

/*
*构造响应报文，在主机中查询到时使用，主要是通过更改查询报文实现的
*buf为询问报文，ip为查询到的IP地址，level为调试等级，只有调试等级为2时，会输出不安全信息
*/
void Respond(char* buf, char* ip, int level) {
	DNSHEADER* header = (DNSHEADER*)buf;
	DNSRESOURCE* resouce;
	/*IP为0.0.0.0响应报文flag中的RCODE为0x3，表示域名不存在*/
	if (ip[0] == (char)0 && ip[1] == (char)0 && ip[2] == (char)0 && ip[3] == (char)0) {
		/*调试等级为2时才会输出*/
		if (level == 2)
			printf("IPaddr is 0.0.0.0, the domainname is unsafe.\n");
		header->Flag = htons(0x8183);
	}
	/*正常情况的响应报文flag为0x8180*/
	else {
		header->Flag = htons(0x8180);
	}
	/*回答数为1*/
	header->Ancount = htons(1);

	char* dn = buf + 12;							//指向报文中的question头
	char* name = dn + strlen(dn) + 1 + 4;			//指向报文中的answer头
	unsigned short* nameTemp = (unsigned short*)name;
	*nameTemp = htons(0xC00C);						//将answer的前两个字节写成0xC0
	/*对answer部分进行填写*/
	resouce = (DNSRESOURCE*)(name + 2);
	resouce->Type = htons(1);
	resouce->Class = htons(1);
	resouce->TTL = htons(0x0FFF);
	resouce->Length = htons(4);
	/*填入IP答案*/
	char* data = (char*)resouce + 10;
	*data = *ip;
	*(data + 1) = *(ip + 1);
	*(data + 2) = *(ip + 2);
	*(data + 3) = *(ip + 3);
}

/*
*调试等级为1时使用，一般只读响应包，用于输出时间和客户端IP地址，以及域名
*/
void PrintAnswerLess(SOCKADDR_IN client, const char* buf) {
	time_t NowTime = time(NULL);
	struct tm* t = localtime(&NowTime);
	printf("\n%d/%02d/%02d,%02d:%02d:%02d  ", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
	printf("Client %d.%d.%d.%d    ", client.sin_addr.S_un.S_un_b.s_b1, client.sin_addr.S_un.S_un_b.s_b2, client.sin_addr.S_un.S_un_b.s_b3, client.sin_addr.S_un.S_un_b.s_b4);

	char* ip = (char*)malloc(4);
	char* p = buf + 12;
	DomainName(p + 1);
}

/*
*调试等级为2时使用，用于读取查询包和响应包，并根据不同类型进行输出
*查询包输出时间、查询类型、以及客户端地址
*相应包则输出时间、答案（包括三种类型IPV4地址、CNAME和PTR指针）、服务器IP和客户端IP
*/
void PrintAnswerMore(SOCKADDR_IN client, const char* buf, char* server_ip) {
	printf("********************************************************************\n");

	time_t NowTime = time(NULL);
	struct tm* t = localtime(&NowTime);
	printf("%d/%02d/%02d,%02d:%02d:%02d\n", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
	char* ip = (char*)malloc(4);
	char* p = buf + 6;						//此时指向ancount，表示答案数量
	unsigned short n = *(unsigned short*)p;	//强制转换成2B的short类型
	n = ntohs(n);							//注意大小端的调整
	p = buf + 12;
	printf("[ID = 0x%x]\n", ntohs((*((unsigned short*)buf)) & 0xFFFF));
	DomainName(p + 1);

	/*tt指向header中的flag，用于判断第一位的QR，为0表示查询，1表示响应*/
	unsigned short* tt = buf + 2;
	/*查询包中的信息输出*/
	if (*tt >> 15 == 0) {
		char* temp = buf + 12;
		temp = temp + strlen(temp) + 1;
		printf("\n[TYPE = %u]\n", ntohs((*(unsigned short*)temp)) & 0xFFFF);
		printf("\nASK FROM CLIENT %d.%d.%d.%d\n", client.sin_addr.S_un.S_un_b.s_b1, client.sin_addr.S_un.S_un_b.s_b2, client.sin_addr.S_un.S_un_b.s_b3, client.sin_addr.S_un.S_un_b.s_b4);
		return;
	}
	/*响应包中的信息输出*/
	printf("\n\n");
	p = p + strlen(p) + 1 + 4;				//p指向第一个answer部分
	for (unsigned short i = 0; i < n; i++) {
		p = p + 2;
		unsigned short type = ntohs(*(unsigned short*)p);	//answer类型
		p = p + 8;
		unsigned short length = ntohs(*(unsigned short*)p);	//answer中的data长度
		/*IPV4地址*/
		if (type == 1) {
			ip = p + 2;
			printf("[IP = %u.%u.%u.%u]\n", *(ip) & 0xff, *(ip + 1) & 0xff, *(ip + 2) & 0xff, *(ip + 3) & 0xff);
		}
		/*CNAME*/
		else if (type == 5) {
			printf("[CNAME = ");
			PrintNameTemp(buf, p + 3);
			printf("]\n");
		}
		/*PTR指针*/
		else if (type == 12) {
			printf("[PTR = ");
			PrintName(p + 3);
			printf("]\n");
		}
		/*IPV6地址，我的电脑从来没收到过IPV6指针，可以写但没必要*/
		else if (type == 28) {
		}
		p = p + 2 + length;
	}
	/*答案数为0*/
	if (n == 0) {
		printf("No answer in this package\n");
	}
	/*输出服务器和客户端信息*/
	printf("\nGET FROM SERVER %s\n", server_ip);
	printf("SEND TO CLIENT %d.%d.%d.%d\n", client.sin_addr.S_un.S_un_b.s_b1, client.sin_addr.S_un.S_un_b.s_b2, client.sin_addr.S_un.S_un_b.s_b3, client.sin_addr.S_un.S_un_b.s_b4);

	printf("********************************************************************\n");
}

/*
*无调试等级时使用
*/
void dns0() {
	char buf[BUFFER_SIZE];		//保存包的信息

	/*准备UDP通信*/
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("error\n");
		exit(1);
	}
	/*创建与客户端沟通的套接字*/
	SOCKET socketFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (socketFd == SOCKET_ERROR) {
		printf("Creat Socket Error\n");
		exit(1);
	}
	/*主机，作为服务器，绑定IP和端口*/
	SOCKADDR_IN server;
	server.sin_family = AF_INET;
	server.sin_port = htons(PORT);
	server.sin_addr.S_un.S_addr = htonl(INADDR_ANY);

	/*客户端，不需要设置信息*/
	SOCKADDR_IN client;

	int z = bind(socketFd, (struct sockaddr*) & server, sizeof(server));
	if (z != 0) {
		printf("bind error\n");
		exit(1);
	}

	/*创建与dns服务器沟通的套接字*/
	SOCKET DnsFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (DnsFd == SOCKET_ERROR) {
		printf("Creat Socket Error\n");
		exit(1);
	}
	/*设置接收非阻塞，防止包丢失后在循环中卡住*/
	int timeout = 2000;
	setsockopt(DnsFd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(int));

	/*dns服务器，绑定IP和端口*/
	SOCKADDR_IN Dns;
	Dns.sin_family = AF_INET;
	Dns.sin_port = htons(PORT);
	Dns.sin_addr.S_un.S_addr = inet_addr(SERVER_IP);

	char* temp = (char*)malloc(BUFFER_SIZE);	//用来存域名
	char* ip = (char*)malloc(4);				//存IP
	unsigned int len = sizeof(client);
	while (1) {
		/*将buf中全填入0*/
		memset(buf, 0, BUFFER_SIZE);

		/*从客户端接收信息，接收失败则进行下一步循环*/
		z = recvfrom(socketFd, buf, BUFFER_SIZE, 0, (struct sockaddr*) & client, &len);
		if (z < 0) {
			continue;
		}
		/*将域名赋值到temp数组中*/
		strcpy(temp, buf + sizeof(DNSHEADER) + 1);
		ToDomainName(temp);
		/*从链表中查询*/
		int ifFind = LookUp(temp, ip, HEAD);

		/*查询到结果则构造响应报文*/
		if (ifFind == 1) {
			Respond(buf, ip, 0);
		}
		/*未查询到，需要从上层的dns服务器进行查询*/
		else if (ifFind == 0) {
			/*将查询包原封不动的发送给dns服务器*/
			sendto(DnsFd, buf, BUFFER_SIZE, 0, (struct sockaddr*) & Dns, sizeof(Dns));

			unsigned short id = *(unsigned short*)buf;
			unsigned short idtemp;
			unsigned int i = sizeof(Dns);
			unsigned int j;
			/*只在响应包与查询包的id相同时才停止接收，
			*由于接收的方式采用了非阻塞，当超过设置的超时时间时，会自动返回一个没有答案的响应包
			*如果dns服务器之前发送的响应包到达比较晚，那么就会与现在所询问的不符合，就会产生所答非所问的情况，所以需要进行一次筛选
			*/
			do
			{
				j = recvfrom(DnsFd, buf, BUFFER_SIZE, 0, (struct sockaddr*) & Dns, &i);
				idtemp = *(unsigned short*)buf;
			} while (idtemp != id);
		}
		/*将响应包原封不动的送个客户端，发送失败则不断重发至发送成功*/
		do
		{
			z = sendto(socketFd, buf, sizeof(buf), 0, (struct sockaddr*) & client, sizeof(client));
		} while (z < 0);
	}
}

/*
*调试等级为1时使用，由于和dns0()函数区别不大，所以只在部分有区别的地方进行解释
*/
void dns1(char* IP, char* file) {
	char buf[BUFFER_SIZE];

	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("error\n");
		exit(1);
	}

	SOCKET socketFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (socketFd == SOCKET_ERROR) {
		printf("Creat Socket Error\n");
		exit(1);
	}
	SOCKADDR_IN server;
	server.sin_family = AF_INET;
	server.sin_port = htons(PORT);
	server.sin_addr.S_un.S_addr = htonl(INADDR_ANY);

	SOCKADDR_IN client;

	int z = bind(socketFd, (struct sockaddr*) & server, sizeof(server));
	if (z != 0) {
		printf("bind error\n");
		exit(1);
	}

	SOCKET DnsFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	int timeout = 2000;
	setsockopt(DnsFd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(int));
	if (DnsFd == SOCKET_ERROR) {
		printf("Creat Socket Error\n");
		exit(1);
	}
	SOCKADDR_IN Dns;
	Dns.sin_family = AF_INET;
	Dns.sin_port = htons(PORT);
	Dns.sin_addr.S_un.S_addr = inet_addr(IP);

	char* temp = (char*)malloc(BUFFER_SIZE);
	char* ip = (char*)malloc(4);
	unsigned int len = sizeof(client);
	while (1) {
		memset(buf, 0, BUFFER_SIZE);
		z = recvfrom(socketFd, buf, BUFFER_SIZE, 0, (struct sockaddr*) & client, &len);
		if (z < 0) {
			continue;
		}
		strcpy(temp, buf + sizeof(DNSHEADER) + 1);
		ToDomainName(temp);

		int ifFind = LookUp(temp, ip, HEAD);

		/*调试等级为1时，还要输出对应的信息*/
		if (ifFind == 1) {
			time_t NowTime = time(NULL);
			struct tm* t = localtime(&NowTime);
			printf("\n%d/%02d/%02d,%02d:%02d:%02d  ", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
			printf("Client %d.%d.%d.%d    ", client.sin_addr.S_un.S_un_b.s_b1, client.sin_addr.S_un.S_un_b.s_b2, client.sin_addr.S_un.S_un_b.s_b3, client.sin_addr.S_un.S_un_b.s_b4);
			DomainName(temp);
			Respond(buf, ip, 1);
		}
		else if (ifFind == 0) {
			sendto(DnsFd, buf, BUFFER_SIZE, 0, (struct sockaddr*) & Dns, sizeof(Dns));

			unsigned short id = *(unsigned short*)buf;
			unsigned short idtemp;
			unsigned int i = sizeof(Dns);
			unsigned int j;
			do
			{
				j = recvfrom(DnsFd, buf, BUFFER_SIZE, 0, (struct sockaddr*) & Dns, &i);
				idtemp = *(unsigned short*)buf;
			} while (idtemp != id);
			/*输出响应包的信息*/
			PrintAnswerLess(client, buf);
		}

		do
		{
			z = sendto(socketFd, buf, sizeof(buf), 0, (struct sockaddr*) & client, sizeof(client));
		} while (z < 0);
	}
}

/*
*同dns1仅解释部分不同代码
*/
void dns2(char* IP) {
	char buf[BUFFER_SIZE];

	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("error\n");
		exit(1);
	}

	SOCKET socketFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (socketFd == SOCKET_ERROR) {
		printf("Creat Socket Error\n");
		exit(1);
	}
	SOCKADDR_IN server;
	server.sin_family = AF_INET;
	server.sin_port = htons(PORT);
	server.sin_addr.S_un.S_addr = htonl(INADDR_ANY);

	SOCKADDR_IN client;

	int z = bind(socketFd, (struct sockaddr*) & server, sizeof(server));
	if (z != 0) {
		printf("bind error\n");
		exit(1);
	}

	SOCKET DnsFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	int timeout = 2000;
	setsockopt(DnsFd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(int));
	if (DnsFd == SOCKET_ERROR) {
		printf("Creat Socket Error\n");
		exit(1);
	}

	SOCKADDR_IN Dns;
	Dns.sin_family = AF_INET;
	Dns.sin_port = htons(PORT);
	Dns.sin_addr.S_un.S_addr = inet_addr(IP);

	char* temp = (char*)malloc(BUFFER_SIZE);
	char* ip = (char*)malloc(4);
	unsigned int len = sizeof(client);
	while (1) {
		memset(buf, 0, BUFFER_SIZE);
		z = recvfrom(socketFd, buf, BUFFER_SIZE, 0, (struct sockaddr*) & client, &len);
		printf("\n\n");
		if (z < 0) {
			continue;
		}
		PrintAnswerMore(client, buf, IP);
		strcpy(temp, buf + sizeof(DNSHEADER) + 1);
		ToDomainName(temp);
		int ifFind = LookUp(temp, ip, HEAD);
		/*输出的信息更多*/
		if (ifFind == 1) {
			printf("********************************************************************\n");
			time_t NowTime = time(NULL);
			struct tm* t = localtime(&NowTime);
			printf("%d/%02d/%02d,%02d:%02d:%02d\n", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
			printf("ASK FROM CLIENT %d.%d.%d.%d\n\n", client.sin_addr.S_un.S_un_b.s_b1, client.sin_addr.S_un.S_un_b.s_b2, client.sin_addr.S_un.S_un_b.s_b3, client.sin_addr.S_un.S_un_b.s_b4);
			printf("[ID = 0x%x]\n", ntohs((*((unsigned short*)buf)) & 0xFFFF));

			DomainName(temp);
			printf("\n[IP = %u.%u.%u.%u]\n", *ip & 0xff, *(ip + 1) & 0xff, *(ip + 2) & 0xff, *(ip + 3) & 0xff);
			Respond(buf, ip, 2);
			printf("\nFind From Host %s\n", LOCAL_IP);
			printf("SEND TO CLIENT %d.%d.%d.%d\n", client.sin_addr.S_un.S_un_b.s_b1, client.sin_addr.S_un.S_un_b.s_b2, client.sin_addr.S_un.S_un_b.s_b3, client.sin_addr.S_un.S_un_b.s_b4);
			printf("********************************************************************\n");
		}
		else if (ifFind == 0) {
			sendto(DnsFd, buf, BUFFER_SIZE, 0, (struct sockaddr*) & Dns, sizeof(Dns));
			unsigned short id = *(unsigned short*)buf;
			unsigned short idtemp;
			unsigned int i = sizeof(Dns);
			unsigned int j;
			do
			{
				j = recvfrom(DnsFd, buf, BUFFER_SIZE, 0, (struct sockaddr*) & Dns, &i);
				idtemp = *(unsigned short*)buf;
			} while (idtemp != id);
			/*输出响应包信息*/
			PrintAnswerMore(client, buf, IP);
		}
		do
		{
			z = sendto(socketFd, buf, sizeof(buf), 0, (struct sockaddr*) & client, sizeof(client));
		} while (z < 0);

	}
}

/*
*main()函数会根据命令行参数的不同，进而执行不同的dns函数
*/
int main(int argc, char* argv[], char* envp[]) {
	printf("\nDNSRELAY, Version 1.4 Build: 2020/08/10 10:39\n");
	printf("Usage: dnsrelay [-d|-dd] [<dns-server>] [<db-file>]\n\n");

	if (argc == 1) {
		printf("调试信息接级别0 无调试信息输出\n");
		printf("指定名字服务器为 %s:53\n", SERVER_IP);
		printf("使用默认配置文件 %s\n", LOCAL_FILE);
		HEAD = OpenFileT(LOCAL_FILE, 0);
		dns0();
	}
	else if (argc == 4 && !strcmp(argv[1], "-d")) {
		printf("调试信息接级别1 简单调试信息输出\n");
		printf("指定名字服务器为 %s:53\n", argv[2]);
		printf("使用指定配置文件 %s\n", argv[3]);
		HEAD = OpenFileT(argv[3], 1);
		dns1(argv[2], argv[3]);
	}
	else if (argc == 3 && !strcmp(argv[1], "-dd")) {
		printf("调试信息接级别2 复杂调试信息输出\n");
		printf("指定名字服务器为 %s:53\n", argv[2]);
		printf("使用默认配置文件 %s\n", LOCAL_FILE);
		HEAD = OpenFileT(LOCAL_FILE, 2);
		//		printf("\n");
		dns2(argv[2]);
	}
	else {
		printf("参数输入有误，请重新输入\n");
	}
	return 0;
}
