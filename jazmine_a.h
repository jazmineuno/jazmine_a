
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

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <errno.h>
#include <zlib.h>
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

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <sys/param.h>
#endif

#if defined(BSD)

#include <sys/event.h>
void watch_loop(int kq);

#endif

#if defined (__linux__)

#include <ev.h>
void read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);

#endif


#define MAX_DATA_SIZE 1024
//8388608
#define NUSERS 256
#define MAXSEED 256
#define MAX_MESSAGE 8192
#define MAXEVENTS 64

struct consensus
{
        std::string ip;
        int timestamp;
        int64_t blockid;
};

struct find_consensus
{
    std::string ip;
    find_consensus(std::string ip) : ip(ip) {}
    bool operator () ( const consensus& c ) const
    {
        return c.ip == ip;
    }
};

sqlite3* db;
std::vector <consensus> seeds;
std::vector <std::string> clients;
volatile sig_atomic_t lookup_flag = false;
volatile bool is_syncing = false;
int srv;
int groupid = 65534;
int userid = 65534;
bool droppriv = true;
int srv_port = 22022;
int max_client_errors = 4;
int pidhandle;
std::string pidfile;
std::string socket_path = "/tmp/jazmine_a.sock";
std::string server_pubkey = "";
std::string server_pk = "";

struct uc
{
        int uc_fd;
        int uc_errors;
        std::string uc_addr;
} users[NUSERS];

struct hi
{
        int64_t blockid;
        std::string hash;
};

enum commands { NOOP,QUIT,GENKEY,GETHEIGHT,GETBLOCK,NEWBLOCK,VALIDATE,GETDATAKEY,GETSENDADDR,GETRECVADDR,GETPUB,GETHASH,HAVENOTS,SIGN,RECVBLOCK };

#define COL_blockid                     0
#define COL_nonce                       1
#define COL_hash                        2
#define COL_link_blockid                3
#define COL_timestamp                   4
#define COL_ttl                         5
#define COL_data_key                    6
#define COL_data                        7
#define COL_sig                         8
#define COL_sendaddr                    9
#define COL_recvaddr                    10
#define COL_validations                 11
#define COL_signatures                  12

static int conn_index(int);
static int conn_add(int,std::string);
static int conn_delete(int);
void remove_seed(int);
std::string json_encode(std::string msg);
void termHandler(int signum);
std::string replacestr(std::string str, const std::string& from, const std::string& to);
std::string escapestr(std::string str);
hi get_last_hash(std::string sendaddr);
std::string bin2hex(const std::string& input);
std::string b_hash(std::string message);
std::string x_randombytes(size_t size);
std::string getpub(int s);
int64_t _getheight();
std::string sign_data(std::string data);
hi gen_hash(std::string sendaddr,std::string recvaddr,std::string data_key,std::string data,int ttl,std::string sig);
std::string getblock(int64_t blockid,int s);
void recvblock(Json::Value rb,int s);
bool _validateblock(Json::Value block);
std::string get_data_key(std::string data_key,int s);
std::string blockid_get_hash(int64_t blockid,int s);
std::string get_sendaddr(std::string sendaddr,int s);
std::string get_havenots(std::string sendaddr,int s);
std::string get_recvaddr(std::string recvaddr,int s);
hi get_hash(int64_t blockid,std::string sendaddr);
std::string validateblock(int64_t blockid,int s);
std::string getheight(int s);
std::string gen_sym_key(int s);
std::string gen_sign_keypair(int s);
std::string gen_box_keypair(int s);
std::string sym_decrypt_text(std::string message, std::string key);
std::string sym_encrypt_text(std::string message, std::string key);
std::string genkey(int s);
commands retval(std::string const& nstr);
void remove_seed(int fd);
void handle_alarm(int sig);
void send_notifies(int64_t blockid);
static void daemonize();
Json::Value parsejson(std::string sq);
void sync_client(int cdx);
void dns_callback (void* arg, int status, int timeouts, struct hostent* host);
void main_loop(ares_channel &channel);
void load_seeds(void);
std::string json_encode(std::string msg);
void recv_msg(int s);
void send_msg(int s, std::string msg, ...);
void *domain_socket(void *);
void *start_server(void *);
bool _addsig(int64_t blockid,std::string hash,std::string sendaddr,std::string sig);
void update_db(Json::Value ux);

