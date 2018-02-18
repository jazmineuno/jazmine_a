#include <ctime>
#include <csignal>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <string>
#include <sstream>
#include <stdint.h>
#include <strings.h>
#include <signal.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <errno.h>
#if defined(__clang__)
#include <vector>
#elif defined(__GNUC__) || defined(__GNUG__)
#include <bits/stdc++.h>
#endif
#include "ares.h" 
#include "json/json.h"
#include "base64.h"
#include "sqlite3.h"
#include <pthread.h>

extern "C" {
#include <sodium.h>
}

#define NUSERS 256
#define MAXSEED 256
#define MAX_MESSAGE 8192

sqlite3* db;
std::vector <std::string> seeds;
std::vector <std::string> clients;
volatile sig_atomic_t lookup_flag = false;
int srv;
int groupid = 65534;
int userid = 65534;
bool droppriv = true;
int srv_port = 22022;
int max_client_errors = 4;
std::string pidfile;

static int conn_index(int);
static int conn_add(int);
static int conn_delete(int);
void remove_seed(int);
std::string json_encode(std::string msg);
void send_msg(int s, std::string msg, ...);

struct uc
{
	int uc_fd;
	int uc_errors;
	std::string uc_addr;
} users[NUSERS];

struct hi
{
	int64_t blockid;
	std::string nonce;
};

enum commands { NOOP,QUIT,NONCE,GETHEIGHT };

#define COL_blockid		0
#define COL_nonce		1
#define COL_sequence		3

void termHandler( int signum )
{
	if ((signum==SIGTERM)||(signum==SIGINT))
	{
		syslog(LOG_NOTICE, "Terminate signal received... shutting down");
        
		for (int i = 0; i<NUSERS; i++)
		{
			if (users[i].uc_fd>0)
			{
				send_msg(users[i].uc_fd,json_encode("Server is shutting down... Goodbye"));
				conn_delete(i);
			}
		}
		sqlite3_close(db);
		::remove(pidfile.c_str());
		syslog(LOG_NOTICE, "End of operation");
		exit(0);
	}
}

std::string replacestr(std::string str, const std::string& from, const std::string& to) {
	size_t start_pos = 0;
	while((start_pos = str.find(from, start_pos)) != std::string::npos)
	{
        str.replace(start_pos, from.length(), to);
        start_pos += to.length();
    }
    return str;
}

std::string escapestr(std::string str)
{
	std::string res(replacestr(str, "'", "''")); 
	return res;
}

std::string bin2hex(const std::string& input)
{
    std::string res;
    const char hex[] = "0123456789abcdef";
    for(auto sc : input)
    {
        unsigned char c = static_cast<unsigned char>(sc);
        res += hex[c >> 4];
        res += hex[c & 0xf];
    }

    return res;
}

std::string x_randombytes(size_t size) {
    std::string buf(size, 0);
    ::randombytes_buf(&buf[0], size);
    return buf;
}

void load_nonce(int cnt)
{
        std::stringstream ss;
        sqlite3_stmt* stmt;

for (int i=0;i<cnt;i++)
{

        std::time_t timestamp = std::time(0);
        std::string nonce(x_randombytes((size_t)32));
        std::string enc_nonce(bin2hex(nonce));

        ss << "INSERT INTO being (nonce,sequence,used) VALUES ('" << escapestr(enc_nonce) << "'," << timestamp << ",0)";
        std::string sql(ss.str());
        if(sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL) != SQLITE_OK)
        {
                sqlite3_close(db);
                sqlite3_finalize(stmt);
                syslog(LOG_NOTICE, "Database error: %s %s (%d)", sqlite3_errmsg(db), sql.c_str(),s);
                return ("Database Error");
        }
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
}

}

std::string get_nonce(int s)
{
	std::stringstream ss;
	sqlite3_stmt* stmt;
	Json::Value root;

	std::time_t timestamp = std::time(0);
	std::string nonce(x_randombytes((size_t)32));
	std::string enc_nonce(bin2hex(nonce));

	ss << "INSERT INTO being (nonce,sequence) VALUES ('" << escapestr(enc_nonce) << "'," << timestamp << ")";
	std::string sql(ss.str());
	if(sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL) != SQLITE_OK)
	{
		sqlite3_close(db);
		sqlite3_finalize(stmt);
		syslog(LOG_NOTICE, "Database error: %s %s (%d)", sqlite3_errmsg(db), sql.c_str(),s);
		return ("Database Error");
	}
	sqlite3_step(stmt);

	int64_t blockid = sqlite3_last_insert_rowid(db);

	root["nonce"]=enc_nonce;
	root["blockid"]=blockid;
	root["sequence"]=timestamp;
	return (root.toStyledString());
}

std::string getheight(int s)
{
	sqlite3_stmt* stmt;
	int64_t blockheight = 0;
	Json::Value root;
	
	std::string sql("SELECT MAX(blockid) FROM blocks");
	if(sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL) != SQLITE_OK)
	{
		sqlite3_close(db);
		sqlite3_finalize(stmt);
		syslog(LOG_NOTICE, "Database error: %s (%d)", sqlite3_errmsg(db),s);
		return ("Database Error");
	}
	int ret_code = 0;
    if ((ret_code = sqlite3_step(stmt)) == SQLITE_ROW) {
		blockheight = sqlite3_column_int64(stmt, 0);
		syslog(LOG_NOTICE, "Blockheight: %lu (%d)",blockheight,s);
    }
	sqlite3_finalize(stmt);
	root["blockheight"]=blockheight;
	return (root.toStyledString());
}

commands retval(std::string const& nstr)
{
	std::string str = nstr;
	str.erase(std::remove(str.begin(), str.end(), '\n'), str.end());
	str.erase(std::remove(str.begin(), str.end(), '\r'), str.end());
	if (str == "nonce") return NONCE;
	if (str == "getheight") return GETHEIGHT;
	if (str == "quit") return QUIT;
	return NOOP;
}

void remove_seed(int fd)
{
	int s = conn_index(fd);
	std::string ip = users[s].uc_addr;
	if (std::find(clients.begin(), clients.end(), ip) != clients.end()) 
	{
		clients.erase(std::remove(clients.begin(), clients.end(), ip), clients.end());
		syslog (LOG_NOTICE, "Client removed %s (%d)", ip.c_str(),fd);
		syslog (LOG_NOTICE, "Clients connected count %lu", clients.size());
	}
	return;
}
	
int conn_index(int fd)
{
    int uidx;
    for (uidx = 0; uidx < NUSERS; uidx++)
        if (users[uidx].uc_fd == fd)
            return uidx;
    return -1;
}

int conn_add(int fd,std::string clientip)
{
    int uidx;
    if (fd < 1) return -1;
    if ((uidx = conn_index(0)) == -1)
        return -1;
    if (uidx == NUSERS) {
        close(fd);
        return -1;
    }
    users[uidx].uc_fd = fd; 
    users[uidx].uc_errors = 0;
    users[uidx].uc_addr = clientip; 
    return 0;
}

int conn_delete(int fd)
{
    int uidx;
    if (fd < 1) return -1;
    if ((uidx = conn_index(fd)) == -1)
        return -1;

    users[uidx].uc_fd = 0;
    users[uidx].uc_errors = 0;
    users[uidx].uc_addr = "";

    return ::close(fd);
}

void handle_alarm( int sig )
{
    lookup_flag = true;
}

static void daemonize()
{
	if (droppriv)
	{
		if (getuid() == 0)
		{
			if (setgid(groupid) != 0)
			{
				syslog (LOG_NOTICE, "Could not drop privileges: %s", strerror(errno));
				exit(1);
			}
			if (setuid(userid) != 0)
			{
				syslog (LOG_NOTICE, "Could not drop privileges: %s", strerror(errno));
				exit(1);
			}
		}
		syslog (LOG_NOTICE, "Dropped privileges to %d:%d",userid,groupid);
	}

	pid_t process_id = 0;
	pid_t sid = 0;
	process_id = fork();
	if (process_id < 0)
	{
		exit(1);
	}
	if (process_id > 0)
	{
		syslog (LOG_NOTICE, "Child process %d", process_id);
		exit(0);
	}
	umask(0);
	sid = setsid();
	if(sid < 0)
	{
		exit(1);
	}
	return;
}

void dns_callback (void* arg, int status, int timeouts, struct hostent* host)
{
	if(!host || status != ARES_SUCCESS)
	{
		syslog (LOG_NOTICE, "Ares Lookup Failed");
        return;
	}
    
	char ip[INET6_ADDRSTRLEN];

	if (seeds.size()<MAXSEED)
	{
		for (int i = 0; host->h_addr_list[i]; ++i)
		{
			inet_ntop(host->h_addrtype, host->h_addr_list[i], ip, sizeof(ip));
			if (std::find(seeds.begin(), seeds.end(), ip) == seeds.end()) 
			{
				seeds.push_back(ip);
				syslog (LOG_NOTICE, "Found seed %s", ip);
				syslog (LOG_NOTICE, "Seed count %lu", seeds.size());
			}
		}
	}
}

void main_loop(ares_channel &channel)
{
    int nfds, count;
    fd_set readers, writers;
    timeval tv, *tvp;
    while (1)
    {
        FD_ZERO(&readers);
        FD_ZERO(&writers);
        nfds = ares_fds(channel, &readers, &writers);
        if (nfds == 0)
          break;
        tvp = ares_timeout(channel, NULL, &tv);
        count = select(nfds, &readers, &writers, NULL, tvp);
        ares_process(channel, &readers, &writers);
     }
}

void load_seeds(void)
{
	struct in_addr ip;
    int res;
    ares_channel channel;
   
    if((res = ares_init(&channel)) != ARES_SUCCESS)
    {
        syslog (LOG_NOTICE, "ares error");
        return;
    }
    
    ares_gethostbyname(channel, "seed1.jazmine.uno", AF_INET, dns_callback, NULL);
    main_loop(channel);
    ares_destroy(channel);
	ares_library_cleanup();
}	

std::string json_encode(std::string msg)
{
	Json::Value root;
	root["response"]=msg;
	return (root.toStyledString());
}

void send_msg(int s, std::string msg, ...) {
    char buf[8192] = {};
    int len;

    va_list ap;
    va_start(ap, msg);
    len = vsnprintf(buf, sizeof(buf), msg.c_str(), ap);
    va_end(ap);
    send(s, buf, len, 0);
}

void recv_msg(int s)
{
    char buf[MAX_MESSAGE] = {0};
    size_t bytes_read;

    bytes_read = ::recv(s, buf, sizeof(buf), 0);
	if (((int)bytes_read > 17)&&(users[conn_index(s)].uc_errors<max_client_errors))
	{
		Json::Value root;
		Json::CharReaderBuilder rbuilder;
		std::stringstream ss;
		ss << buf;
		rbuilder["collectComments"] = false;
		std::string errs;
		bool isok = Json::parseFromStream(rbuilder, ss, &root, &errs);
		if (!isok)
		{
				send_msg(s, json_encode("Invalid Json"));
				users[conn_index(s)].uc_errors++;
				syslog (LOG_NOTICE, "User errors on FD %d raised to %d",s,users[conn_index(s)].uc_errors);
		} else {
				std::string command = root["command"].asString();
				switch (retval(command))
				{
					case NONCE:
						send_msg(s, get_nonce(s));
						break;
					case GETHEIGHT:
						send_msg(s, getheight(s));
						break;
					case QUIT:
						send_msg(s, json_encode("Goodbye"));
						syslog(LOG_NOTICE, "Client Disconnect");
						remove_seed(s);
						conn_delete(s);
						break;
					case NOOP: /* fallthrough */
					default:
						send_msg(s, json_encode("Error Invalid Command"));
						users[conn_index(s)].uc_errors++;
						syslog (LOG_NOTICE, "Error: Invalid Command");
						syslog (LOG_NOTICE, "User errors on (%d) raised to %d",s,users[conn_index(s)].uc_errors);
						break;
			}
		}
	} else {
		send_msg(s, json_encode("Invalid Json"));
		users[conn_index(s)].uc_errors++;
		syslog (LOG_NOTICE, "User errors on (%d) raised to %d",s,users[conn_index(s)].uc_errors);
	}
}

/* based on Eric Radman kevent example http://eradman.com/ */

void watch_loop(int kq)
{
	
	struct kevent evSet;
    struct kevent evList[32];
    int nev, i;
    struct sockaddr_in addr;
    socklen_t socklen = sizeof(addr);
    int fd;

    while(1) {
        nev = kevent(kq, NULL, 0, evList, 32, NULL);
        if (nev < 1)
        {
            syslog(LOG_NOTICE, "kevent error");
            exit(1);
        }
        for (i=0; i<nev; i++) {
            if (evList[i].flags & EV_EOF) {
                syslog(LOG_NOTICE, "Client Disconnect");
                fd = evList[i].ident;
                remove_seed(fd);
				conn_delete(fd);
/*                EV_SET(&evSet, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
                if (kevent(kq, &evSet, 1, NULL, 0, NULL) == -1)
                {
                    syslog(LOG_NOTICE, "kevent error");
                }
                */

            }
            else if (evList[i].ident == srv) {
                fd = accept(evList[i].ident, (struct sockaddr *)&addr,
                    &socklen);
                if (fd == -1)
                {
                    syslog(LOG_NOTICE, "accept error");
                }
                std::string clientip = inet_ntoa(addr.sin_addr);
                if (conn_add(fd,clientip) == 0) {
                    EV_SET(&evSet, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
                    if (kevent(kq, &evSet, 1, NULL, 0, NULL) == -1)
                    {
						syslog(LOG_NOTICE, "kevent error");
					} else {
						send_msg(fd, json_encode("welcome!"));
						syslog(LOG_NOTICE, "Client Connected %s",clientip.c_str());
						if (clients.size()<NUSERS)
						{
							if (std::find(clients.begin(), clients.end(), clientip) == clients.end()) 
							{
								clients.push_back(clientip);
								syslog (LOG_NOTICE, "Added client %s", clientip.c_str());
								syslog (LOG_NOTICE, "Connected clients count %lu", clients.size());
							}
						}
					}
                } else {
					syslog(LOG_NOTICE, "Client Connection Refused");
                    close(fd);
                }
            }
            else {
                recv_msg(evList[i].ident);
            }
        }
    }
}

void *start_server(void *)
{
	int kq;
	struct kevent evSet;
	struct sockaddr_in sa;
	
	srv = ::socket(PF_INET, SOCK_STREAM, 0);
    bzero(&sa,sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY); //INADDR_LOOPBACK
    sa.sin_port = htons( srv_port );

	if (::bind(srv, (struct sockaddr *)&sa, sizeof(sa))<0)
	{
		syslog(LOG_NOTICE, "Error bind");
	}
	fork();
	
    ::listen(srv, 5);
    
    syslog(LOG_NOTICE, "Started Listening on %s:%d",inet_ntoa(sa.sin_addr),ntohs(sa.sin_port));
    
    kq = kqueue();
    
    EV_SET(&evSet, srv, EVFILT_READ, EV_ADD, 0, 0, NULL);
    
	if (kevent(kq, &evSet, 1, NULL, 0, NULL) == -1)
	{
		syslog(LOG_NOTICE, "kevent error");
		exit(1);
	}
    
    watch_loop(kq);
    
    for (;;) {}
    return (0);
}

     
int main(int argc, char* argv[])
{
	pthread_t srv_thread_id, alarm_thread_id;
	sqlite3_stmt* stmt;
	int dns_ttl = 60;
	bool daemon = true;
	std::string config_file = "jazmine_a.json";
	
	if (argc>1)
	{
		if (strcmp(argv[1],"-c")==0)
		{
			config_file = argv[2];
		} else if (strcmp(argv[1],"-h")==0)
		{
			std::cout << "jazmine_a 1.1.1.1 copyright 2018 Waitman Gobble" << std::endl << std::endl;
		}
	}
	
	setlogmask (LOG_UPTO (LOG_NOTICE));
	openlog ("central_being", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
	syslog(LOG_NOTICE, "Started by uid %d", getuid());
	
	Json::Value root;
	std::ifstream file(config_file);
	syslog(LOG_NOTICE, "Config file %s", config_file.c_str());
	if (file.good())
	{
		syslog(LOG_NOTICE, "Config file exists");
	} else {
		syslog(LOG_NOTICE, "Config file does not exist, using defaults");
	}
	std::string dbfile = root.get("dbfile","central_being.db").asString();
	syslog(LOG_NOTICE, "DB File %s", dbfile.c_str());
	pidfile = root.get("pidfile","/var/run/central_being.pid").asString();
	syslog(LOG_NOTICE, "pid File %s", pidfile.c_str());
	userid = root.get("userid",65534).asInt();
	groupid = root.get("groupid",65534).asInt();
	droppriv = root.get("droppriv",true).asBool();
	srv_port = root.get("srv_port",22322).asInt();
	dns_ttl = root.get("dns_ttl",60).asInt();
	if (dns_ttl<60) dns_ttl = 60;
	syslog(LOG_NOTICE, "DNS TTL %d", dns_ttl);
	max_client_errors = root.get("max_client_errors",4).asInt();
	syslog(LOG_NOTICE, "Max Client Errors %d", max_client_errors);
	
	daemon = root.get("daemon",true).asBool();

	int pid_file = open(pidfile.c_str(), O_CREAT | O_RDWR, 0666);
	int rc = flock(pid_file, LOCK_EX | LOCK_NB);
	if (rc)
	{
		if(EWOULDBLOCK == errno)
		{
			syslog(LOG_NOTICE, "Another central_being process is already running");
			exit(1);
		}
	}

	std::signal(SIGINT, termHandler);
	std::signal(SIGTERM, termHandler);
	
	if(sqlite3_open(dbfile.c_str(), &db) != SQLITE_OK) {
		syslog(LOG_NOTICE, "Error: Cannot open database: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }
    
	std::string sql("SELECT MAX(blockid) FROM being");
	if(sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL) != SQLITE_OK)
	{
		std::string createdb("CREATE TABLE being (blockid INTEGER PRIMARY KEY, nonce TEXT,sequence INTEGER,used INTEGER);");
		if(sqlite3_prepare_v2(db, createdb.c_str(), -1, &stmt, NULL) != SQLITE_OK)
		{
			sqlite3_close(db);
			sqlite3_finalize(stmt);
			syslog(LOG_NOTICE, "Could not create database: %s", sqlite3_errmsg(db));
			return 1;
		}
		syslog(LOG_NOTICE, "Database tables created");
	}
	int ret_code = 0;
    if ((ret_code = sqlite3_step(stmt)) == SQLITE_ROW) {
		int64_t blockheight = sqlite3_column_int(stmt, 0);
		syslog(LOG_NOTICE, "Blockheight: %lu",blockheight);
    }
	sqlite3_finalize(stmt);

    pthread_create(&srv_thread_id, NULL, start_server, (void *) NULL);
    
    if (daemon)
    {
		daemonize();
	}

	std::signal(SIGALRM, handle_alarm); 
	seeds.clear();
	
	load_seeds();
	alarm(dns_ttl);

	for (;;)
	{
		if (lookup_flag)
		{
			lookup_flag = false;
			load_seeds();
			alarm(dns_ttl);
		}
	}
	
	return 0;
}
