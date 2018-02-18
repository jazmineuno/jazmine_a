/*
 * Copyright (c) 2018, Waitman Gobble <ns@waitman.net>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "jazmine_a.h"

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
		::close(pidhandle);
		syslog(LOG_NOTICE, "End of operation");
		exit(EXIT_SUCCESS);
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

hi get_last_hash(std::string sendaddr)
{
	std::stringstream ss;
	sqlite3_stmt* stmt;
	hi hash_index;
	hash_index.blockid = 0;
	hash_index.hash = "";

	if (sendaddr=="")
	{
		syslog(LOG_NOTICE, "Error: get_last_hash No Send Address");
		return (hash_index);
	} else {
		ss << "SELECT blockid,hash FROM blocks WHERE sendaddr='" << escapestr(sendaddr) << "' ORDER BY blockid DESC";
		std::string sql(ss.str());
		
		int sqlerr = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);
		if(sqlerr != SQLITE_OK)
		{
			syslog(LOG_NOTICE, "Error: get_last_hash Database error %d %s",sqlerr,sql.c_str());
			sqlite3_finalize(stmt);
			return (hash_index);
		} else {
			int ret_code = 0;
			if ((ret_code = sqlite3_step(stmt)) == SQLITE_ROW)
			{
				hash_index.blockid = (int64_t) sqlite3_column_int64(stmt, 0);
				hash_index.hash = std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)));
			} else {
				hash_index.blockid = 0;
				hash_index.hash = sendaddr; //genesis
			}
			sqlite3_finalize(stmt);
		}
	}
	return (hash_index);
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

std::string b_hash(std::string message)
{
	unsigned char hash[crypto_generichash_BYTES];

	crypto_generichash(hash, sizeof hash,
		reinterpret_cast<const unsigned char*>(message.data()), message.length(),
		NULL, 0);
	
	std::string bhash(hash, hash + sizeof hash / sizeof hash[0]);

	return bin2hex(bhash);
}

std::string x_randombytes(size_t size)
{
    std::string buf(size, 0);
    ::randombytes_buf(&buf[0], size);
    return buf;
}

std::string getpub(int s)
{
	Json::Value root;
	root["pubkey"]=server_pubkey;
	return (root.toStyledString());
}

int64_t _getheight()
{
	sqlite3_stmt* stmt;
	int64_t blockheight = 0;
	
	std::string sql("SELECT MAX(blockid) FROM blocks");
	if(sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL) != SQLITE_OK)
	{
		sqlite3_close(db);
		sqlite3_finalize(stmt);
		syslog(LOG_NOTICE, "Database error: %s", sqlite3_errmsg(db));
		return (0);
	}
	int ret_code = 0;
    if ((ret_code = sqlite3_step(stmt)) == SQLITE_ROW)
    {
		blockheight = sqlite3_column_int64(stmt, 0);
    }
	sqlite3_finalize(stmt);
	return (blockheight);
}

std::string sign_data(std::string data)
{
	unsigned char sig[crypto_sign_BYTES];
	crypto_sign_detached(sig, NULL, reinterpret_cast<const unsigned char*>(data.data()), data.length(), reinterpret_cast<const unsigned char*>(server_pk.data()));
	std::string signature( sig, sig + sizeof sig / sizeof sig[0] );
	return signature;
}

hi gen_hash(std::string sendaddr,std::string recvaddr,std::string data_key,std::string data,int ttl,std::string sig)
{
	char *zErrMsg = 0;
    hi previous_hash = get_last_hash(sendaddr);
    hi hash_index;
    int64_t nextid;
    hash_index.blockid=0;
	hash_index.hash="";
	std::time_t timestamp = std::time(0);

	nextid = _getheight() + 1;
	
    std::string pubkey = base64_decode(sendaddr.substr(4,sendaddr.length()-4));
    
    std::string dec_sig = base64_decode(sig);
    
    if (pubkey.length()<(crypto_box_PUBLICKEYBYTES+crypto_sign_PUBLICKEYBYTES))
	{
		syslog(LOG_NOTICE, "Error: gen_hash Invalid pubkey");
		return hash_index;
	}
	std::string box_pub = pubkey.substr(0,crypto_box_PUBLICKEYBYTES);
	std::string sign_pub = pubkey.substr(crypto_box_PUBLICKEYBYTES,crypto_sign_PUBLICKEYBYTES);
	
	if (crypto_sign_verify_detached(reinterpret_cast<const unsigned char*>(dec_sig.data()), 
			reinterpret_cast<const unsigned char*>(data.data()), 
			data.length(), 
			reinterpret_cast<const unsigned char*>(sign_pub.data())) != 0)
	{
		syslog(LOG_NOTICE, "Error: gen_hash Invalid Signature");
		return hash_index;
	}

	syslog(LOG_NOTICE, "Success: gen_hash VALID Signature");
	
	std::string nonce(x_randombytes((size_t)32));
	std::string enc_nonce(base64_encode(reinterpret_cast<const unsigned char*>(nonce.data()), nonce.length()));
	
	std::stringstream hashbuilder;
	hashbuilder << enc_nonce << previous_hash.hash << previous_hash.blockid << data_key << ttl << sig << data << sendaddr << recvaddr << nextid;
	std::string newhash = b_hash(hashbuilder.str());
	syslog(LOG_NOTICE, "Success: gen_hash VALID hash %s" , newhash.c_str());
	
	std::string sql = 
		"INSERT INTO blocks (blockid,nonce,hash,link_blockid,timestamp,ttl,data_key,data,sig,sendaddr,recvaddr,validations,signatures) VALUES ("
		+ std::to_string(nextid)				+ ",'"
		+ escapestr(enc_nonce)					+ "','"
		+ escapestr(newhash)					+ "',"
		+ std::to_string(previous_hash.blockid)	+ ","
		+ std::to_string(timestamp)				+ ","
		+ std::to_string(ttl)					+ ",'"
		+ data_key								+ "','"
		+ base64_encode(reinterpret_cast<const unsigned char*>(data.data()),data.length())	+ "','"
		+ base64_encode(reinterpret_cast<const unsigned char*>(sig.data()),sig.length())	+ "','"
		+ sendaddr								+ "','"
		+ recvaddr								+ "',0,'');";
	
	int rc = sqlite3_exec(db, sql.c_str(), NULL, 0, &zErrMsg);
	if( rc != SQLITE_OK ){
		syslog (LOG_NOTICE, "SQL Error: %s\n",zErrMsg);
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	} else {
		hash_index.blockid = nextid;
		hash_index.hash = newhash;
		syslog (LOG_NOTICE, "Created Block %ld",nextid);
		notifies.push_back(nextid);
	}
	return hash_index;
}

std::string getblock(int64_t blockid,int s)
{
	sqlite3_stmt* stmt;
	std::stringstream ss;
	std::string result;

	syslog(LOG_NOTICE, "Get Block: %lu (%d)",blockid,s);
	
	ss << "SELECT * FROM blocks WHERE blockid = " << blockid;
	std::string sql(ss.str());
	if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL) != SQLITE_OK)
	{
		result = json_encode("Database Error");
	} else {
		int ret_code = 0;
		if ((ret_code = sqlite3_step(stmt)) == SQLITE_ROW)
		{
			Json::Value root;
			root["blockid"]			= (int64_t) sqlite3_column_int64(stmt, COL_blockid);
			root["nonce"]			= reinterpret_cast<const char*>(sqlite3_column_text(stmt, COL_nonce));
			root["hash"]			= reinterpret_cast<const char*>(sqlite3_column_text(stmt, COL_hash));
			root["link_blockid"]	= (int64_t) sqlite3_column_int64(stmt, COL_link_blockid);
			root["timestamp"]		= (int) sqlite3_column_int(stmt, COL_timestamp);
			root["ttl"]				= (int) sqlite3_column_int(stmt, COL_ttl);
			root["data_key"]		= reinterpret_cast<const char*>(sqlite3_column_text(stmt, COL_data_key));
				std::string dt(reinterpret_cast<const char*>(sqlite3_column_text(stmt, COL_data)));
			root["data"]			= base64_decode(dt);
				std::string sg(reinterpret_cast<const char*>(sqlite3_column_text(stmt, COL_sig)));
			root["sig"]				= base64_decode(sg);
			root["sendaddr"]		= reinterpret_cast<const char*>(sqlite3_column_text(stmt, COL_sendaddr));
			root["recvaddr"]		= reinterpret_cast<const char*>(sqlite3_column_text(stmt, COL_recvaddr));
			root["validations"]		= (int) sqlite3_column_int(stmt, COL_validations);
			root["signatures"]		= reinterpret_cast<const char*>(sqlite3_column_text(stmt, COL_signatures));
			/*
				std::string si(reinterpret_cast<const char*>(sqlite3_column_text(stmt, COL_signatures)));

				if (si.length()>0)
				{
					size_t pos = 0;
					std::string token;
					std::string delimiter("\n");
					std::string exp = ":";
					while ((pos = si.find(delimiter)) != std::string::npos)
					{
						token = si.substr(0, pos);
						std::string this_sig = token;
						size_t cpos = token.find(exp);
						std::string saddr = token.substr(0,cpos);
						token.erase(0,cpos+exp.length());
						root["signatures"][saddr] = token;
						si.erase(0, pos + delimiter.length());
					}
                                        size_t cpos = si.find(exp);
                                        std::string saddr = si.substr(0,cpos);
                                        si.erase(0,cpos+exp.length());
                                        root["signatures"][saddr] = si;
				}
				*/
					
			result = root.toStyledString();
		} else {
			result = json_encode("Block not found");
			syslog(LOG_NOTICE, "Error: Block not found %lu (%d)",blockid,s);
		}
	}
	sqlite3_finalize(stmt);
	return (result);
}

bool _addsig(int64_t blockid,std::string hash,std::string sendaddr,std::string sig)
{
	sqlite3_stmt* stmt;
	std::stringstream ss;

	if (hash.length()<32) return false;
	if (sig.length()<32) return false;
	if (sendaddr.length()<32) return false;

	std::string pubkey = base64_decode(sendaddr.substr(4,sendaddr.length()-4));
	std::string dec_sig = base64_decode(sig);
	if (pubkey.length()<(crypto_box_PUBLICKEYBYTES+crypto_sign_PUBLICKEYBYTES))
        {
		syslog(LOG_NOTICE, "Error: gen_hash Invalid pubkey");
		return false;
	}
	std::string box_pub = pubkey.substr(0,crypto_box_PUBLICKEYBYTES);
	std::string sign_pub = pubkey.substr(crypto_box_PUBLICKEYBYTES,crypto_sign_PUBLICKEYBYTES);
	
	if (crypto_sign_verify_detached(reinterpret_cast<const unsigned char*>(dec_sig.data()),
		reinterpret_cast<const unsigned char*>(hash.c_str()),
		hash.length(),
		reinterpret_cast<const unsigned char*>(sign_pub.data())) != 0)
	{
		syslog(LOG_NOTICE, "Error: _addsig Invalid Signature");
		return false;
	}
	syslog(LOG_NOTICE, "Success: _addsig VALID Signature");

	ss << "SELECT validations,signatures FROM blocks WHERE blockid = " << blockid << " AND hash = '" << escapestr(hash) << "'";
	std::string sql(ss.str());
	if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL) != SQLITE_OK)
	{
		sqlite3_finalize(stmt);
		syslog(LOG_NOTICE,"sql query failed. %s",sql.c_str());
		return false;
	} else {
		int ret_code = 0;
		ret_code = sqlite3_step(stmt);
		if (ret_code == SQLITE_ROW)
		{
			int validations = (int) sqlite3_column_int(stmt, 0);
			std::string signatures(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)));
			validations++;
			if (validations>1)
			{
				signatures = signatures + "\n" + sendaddr + ":" + sig;
			} else {
				signatures = sendaddr + ":" + sig;
			}
			sqlite3_finalize(stmt);
			std::string isql("UPDATE blocks SET validations = " + std::to_string(validations) + ", signatures='" + escapestr(signatures) +"' WHERE blockid = " + std::to_string(blockid) + " AND hash='" + escapestr(hash) + "'");
			if (sqlite3_prepare_v2(db, isql.c_str(), -1, &stmt, NULL) != SQLITE_OK)
			{
				syslog (LOG_NOTICE,"sql update failed. %s", isql.c_str());
				sqlite3_finalize(stmt);
				return false;
			}
			char *zErrMsg = 0;
			int rc = sqlite3_exec(db, isql.c_str(), NULL, 0, &zErrMsg);
			if( rc != SQLITE_OK )
			{
				syslog (LOG_NOTICE,"sql update failed. %s", isql.c_str());
                                sqlite3_finalize(stmt);
                                return false;
			}
			sqlite3_finalize(stmt);
			syslog (LOG_NOTICE,"updated validations and signatures blockid: %ld",blockid);
		} else {
			syslog(LOG_NOTICE,"sql select failed. %s", sql.c_str());
			sqlite3_finalize(stmt);
			return false;
		}
	}	
	return true;
}

bool _validateblock(Json::Value block)
{
	sqlite3_stmt* stmt;
	std::stringstream ss;
	std::string result;

	int64_t blockid;
	std::string nonce;
	std::string data;
	std::string sig;
	std::string ohash;
	int64_t link_blockid;
	int timestamp;
	int ttl;
	std::string data_key;
	std::string recvaddr;
	std::string sendaddr;
	bool perform = false;

	blockid = (int64_t) block.get("blockid",0).asInt64();
	nonce = block.get("nonce","").asString();
	data = base64_decode(block.get("data","").asString());
	sig = base64_decode(block.get("sig","").asString());
	ohash = block.get("hash","").asString();
	link_blockid = (int64_t) block.get("link_blockid",0).asInt64();
	timestamp = (int) block.get("timestamp",0).asInt();
	ttl = (int) block.get("ttl",0).asInt();
	data_key = block.get("data_key","").asString();
	recvaddr = block.get("recvaddr","").asString();
	sendaddr = block.get("sendaddr","").asString();
	
	hi previous_hash = get_hash(link_blockid,sendaddr);
	std::stringstream hashbuilder;
	hashbuilder << nonce << previous_hash.hash << link_blockid << data_key << ttl << sig << data << sendaddr << recvaddr << blockid;
	std::string newhash = b_hash(hashbuilder.str());
	if (newhash==ohash)
	{
		perform = true;
	}
	return (perform);
}

std::string get_data_key(std::string data_key,int s)
{
	sqlite3_stmt* stmt;
	std::stringstream ss;
	std::string result;
	Json::Value root;
	bool found = false;
	syslog(LOG_NOTICE, "Get Data Key: %s (%d)",data_key.c_str(),s);
	
	ss << "SELECT * FROM blocks WHERE data_key = '" << escapestr(data_key) << "' ORDER BY blockid ASC";
	std::string sql(ss.str());
	if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL) != SQLITE_OK)
	{
		result = json_encode("Database Error");
	} else {
		int ret_code = 0;
		while ((ret_code = sqlite3_step(stmt)) == SQLITE_ROW)
		{
			root[std::to_string((int64_t) sqlite3_column_int64(stmt, COL_blockid))] = (int) sqlite3_column_int(stmt, COL_timestamp);
			found = true;
		}
		result = root.toStyledString();
	}
	sqlite3_finalize(stmt);
	if (!found)
	{
		result = json_encode("Data Key not found");
		syslog(LOG_NOTICE, "Error: Data Key not found %s (%d)",data_key.c_str(),s);
	}
	return (result);
}

std::string blockid_get_hash(int64_t blockid,int s)
{
        sqlite3_stmt* stmt;
        std::stringstream ss;
        std::string result;
        Json::Value root;
        bool found = false;
        syslog(LOG_NOTICE, "Get Hash : %ld (%d)",blockid,s);

        ss << "SELECT hash FROM blocks WHERE blockid = " << blockid;
        std::string sql(ss.str());
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL) != SQLITE_OK)
        {
                result = json_encode("Database Error");
        } else {
                int ret_code = 0;
                while ((ret_code = sqlite3_step(stmt)) == SQLITE_ROW)
                {
			root["hash"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                        found = true;
                }
                result = root.toStyledString();
        }
        sqlite3_finalize(stmt);
        if (!found)
        {
                result = json_encode("Blockid not found");
                syslog(LOG_NOTICE, "Error: Blockid not found %ld (%d)",blockid,s);
        }
        return (result);
}

std::string get_sendaddr(std::string sendaddr,int s)
{
	sqlite3_stmt* stmt;
	std::stringstream ss;
	std::string result;
	Json::Value root;
	bool found = false;
//	syslog(LOG_NOTICE, "Get SendAddr: %s (%d)",sendaddr.c_str(),s);
	
	ss << "SELECT * FROM blocks WHERE sendaddr = '" << escapestr(sendaddr) << "' ORDER BY blockid ASC";
	std::string sql(ss.str());
	if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL) != SQLITE_OK)
	{
		result = json_encode("Database Error");
	} else {
		int ret_code = 0;
		while ((ret_code = sqlite3_step(stmt)) == SQLITE_ROW)
		{
			root[std::to_string((int64_t) sqlite3_column_int64(stmt, COL_blockid))] = (int) sqlite3_column_int(stmt, COL_timestamp);
			found = true;
		}
		result = root.toStyledString();
	}
	sqlite3_finalize(stmt);
	if (!found)
	{
		result = json_encode("SendAddr not found");
		//syslog(LOG_NOTICE, "Error: SendAddr not found %s (%d)",sendaddr.c_str(),s);
	}
	return (result);
}

std::string get_havenots(std::string sendaddr,int s)
{
        sqlite3_stmt* stmt;
        std::stringstream ss;
        std::string result;
        Json::Value root;
        bool found = false;
	int cnt = 0;
        //syslog(LOG_NOTICE, "Get HaveNots: %s (%d)",sendaddr.c_str(),s);

        ss << "SELECT * FROM blocks WHERE signatures NOT LIKE '%" << escapestr(sendaddr) << "%' ORDER BY blockid ASC";
        std::string sql(ss.str());
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL) != SQLITE_OK)
        {
                result = json_encode("Database Error");
        } else {
                int ret_code = 0;
                while ((ret_code = sqlite3_step(stmt)) == SQLITE_ROW)
                {
                        root[std::to_string((int64_t) sqlite3_column_int64(stmt, COL_blockid))] = (int) sqlite3_column_int(stmt, COL_timestamp);
                        found = true;
			cnt++;
                }
		root["count"]=cnt;
                result = root.toStyledString();
        }
        sqlite3_finalize(stmt);
        if (!found)
        {
		root["count"]=0;
                result = root.toStyledString();
                //syslog(LOG_NOTICE, "Notice: SendAddr not found %s (%d)",sendaddr.c_str(),s);
        }
        return (result);
}

std::string get_recvaddr(std::string recvaddr,int s)
{
	sqlite3_stmt* stmt;
	std::stringstream ss;
	std::string result;
	Json::Value root;
	bool found = false;
	syslog(LOG_NOTICE, "Get RecvAddr: %s (%d)",recvaddr.c_str(),s);
	
	ss << "SELECT * FROM blocks WHERE recvaddr = '" << escapestr(recvaddr) << "' ORDER BY blockid ASC";
	std::string sql(ss.str());
	if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL) != SQLITE_OK)
	{
		result = json_encode("Database Error");
	} else {
		int ret_code = 0;
		while ((ret_code = sqlite3_step(stmt)) == SQLITE_ROW)
		{
			root[std::to_string((int64_t) sqlite3_column_int64(stmt, COL_blockid))] = (int) sqlite3_column_int(stmt, COL_timestamp);
			found = true;
		}
		result = root.toStyledString();
	}
	sqlite3_finalize(stmt);
	if (!found)
	{
		result = json_encode("RecvAddr not found");
		syslog(LOG_NOTICE, "Error: RecvAddr not found %s (%d)",recvaddr.c_str(),s);
	}
	return (result);
}

hi get_hash(int64_t blockid,std::string sendaddr)
{
	std::stringstream ss;
	sqlite3_stmt* stmt;
	hi hash_index;
	hash_index.blockid = 0;
	hash_index.hash = "";

	if (sendaddr=="")
	{
		syslog(LOG_NOTICE, "Error: get_hash No Send Address");
		return (hash_index);
	} else {
		if (blockid==0)
		{
			hash_index.hash = sendaddr; //genesis
		} else {
			ss << "SELECT hash FROM blocks WHERE sendaddr='" << escapestr(sendaddr) << "' AND blockid=" << blockid;
			std::string sql(ss.str());
		
			int sqlerr = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);
			if(sqlerr != SQLITE_OK)
			{
				syslog(LOG_NOTICE, "Error: get_last_hash Database error %d %s",sqlerr,sql.c_str());
				sqlite3_finalize(stmt);
				return (hash_index);
			} else {
				int ret_code = 0;
				if ((ret_code = sqlite3_step(stmt)) == SQLITE_ROW)
				{
					hash_index.blockid = blockid;
					hash_index.hash = std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
				} else {
					hash_index.blockid = 0;
					hash_index.hash = "";
				}
				sqlite3_finalize(stmt);
			}
		}
	}
	return (hash_index);
}

std::string validateblock(int64_t blockid,int s)
{
	sqlite3_stmt* stmt;
	std::stringstream ss;
	std::string result;

	std::string nonce;
	std::string data;
	std::string sig;
	std::string ohash;
	int64_t link_blockid;
	int timestamp;
	int ttl;
	std::string data_key;
	std::string recvaddr;
	std::string sendaddr;
	bool perform = false;
	
	syslog(LOG_NOTICE, "Validate Block: %lu (%d)",blockid,s);
	
	ss << "SELECT * FROM blocks WHERE blockid = " << blockid;
	std::string sql(ss.str());
	if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL) != SQLITE_OK)
	{
		result = json_encode("Database Error");
	} else {
		int ret_code = 0;
		if ((ret_code = sqlite3_step(stmt)) == SQLITE_ROW)
		{
			nonce = reinterpret_cast<const char*>(sqlite3_column_text(stmt, COL_nonce));
			syslog(LOG_NOTICE,"nonce %s",nonce.c_str());
			std::string dt(reinterpret_cast<const char*>(sqlite3_column_text(stmt, COL_data)));
			data = base64_decode(dt);
			syslog(LOG_NOTICE,"data %s",data.c_str());
			std::string sg(reinterpret_cast<const char*>(sqlite3_column_text(stmt, COL_sig)));
			sig = base64_decode(sg);
			syslog(LOG_NOTICE,"sig %s",sig.c_str());
			ohash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, COL_hash));
			syslog(LOG_NOTICE,"hash %s",ohash.c_str());
			link_blockid = (int64_t) sqlite3_column_int64(stmt, COL_link_blockid);
			syslog(LOG_NOTICE,"nonce %ld",link_blockid);
			timestamp = (int) sqlite3_column_int(stmt, COL_timestamp);
			syslog(LOG_NOTICE,"nonce %d",timestamp);
			ttl = (int) sqlite3_column_int(stmt, COL_ttl);
			syslog(LOG_NOTICE,"nonce %d",ttl);
			data_key = reinterpret_cast<const char*>(sqlite3_column_text(stmt, COL_data_key));
			syslog(LOG_NOTICE,"datakey %s",data_key.c_str());
			recvaddr = reinterpret_cast<const char*>(sqlite3_column_text(stmt, COL_recvaddr));
			syslog(LOG_NOTICE,"recvaddr %s",recvaddr.c_str());
			sendaddr = reinterpret_cast<const char*>(sqlite3_column_text(stmt, COL_sendaddr));
			syslog(LOG_NOTICE,"sendaddr %s",sendaddr.c_str());
			perform = true;
		} else {
			result = "Block not found";
			syslog(LOG_NOTICE, "Error: Block not found %lu (%d)",blockid,s);
		}
	}
	sqlite3_finalize(stmt);

		if (perform)
		{
			hi previous_hash = get_hash(link_blockid,sendaddr);
			syslog(LOG_NOTICE,"prev %ld %s",previous_hash.blockid,previous_hash.hash.c_str());
			std::stringstream hashbuilder;
			hashbuilder << nonce << previous_hash.hash << link_blockid << data_key << ttl << sig << data << sendaddr << recvaddr << blockid;
			std::string newhash = b_hash(hashbuilder.str());
			syslog(LOG_NOTICE,"check hash %s",newhash.c_str());
			if (newhash!=ohash)
			{
				result = "Invalid Block";
			} else {
				result = "Block Validated";
			}
		}

	Json::Value root;
	root["result"] = result;
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
    if ((ret_code = sqlite3_step(stmt)) == SQLITE_ROW)
    {
		blockheight = sqlite3_column_int64(stmt, 0);
		syslog(LOG_NOTICE, "Blockheight: %lu (%d)",blockheight,s);
    }
	sqlite3_finalize(stmt);
	root["blockheight"]=blockheight;
	return (root.toStyledString());
}

std::string gen_sym_key(int s)
{
    unsigned char ukey[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
	::crypto_aead_chacha20poly1305_ietf_keygen(ukey);
	std::string key( ukey, ukey + sizeof ukey / sizeof ukey[0] );
	return key;
}

std::string gen_sign_keypair(int s)
{
	unsigned char pk[crypto_sign_PUBLICKEYBYTES];
	unsigned char sk[crypto_sign_SECRETKEYBYTES];
	crypto_sign_keypair(pk, sk);

	std::string encpk(pk, pk + sizeof pk / sizeof pk[0]);
    std::string encsk(sk, sk + sizeof sk / sizeof sk[0]);

    return (encsk+encpk);
}

std::string gen_box_keypair(int s)
{
	unsigned char pk[crypto_box_PUBLICKEYBYTES];
	unsigned char sk[crypto_box_SECRETKEYBYTES];
	crypto_box_keypair(pk, sk);
	
	std::string encpk(pk, pk + sizeof pk / sizeof pk[0]);
    std::string encsk(sk, sk + sizeof sk / sizeof sk[0]);

	return (encsk+encpk);
}

std::string sym_decrypt_text(std::string message, std::string key)
{
	std::string plaintext = "";
	unsigned long long ciphertext_len;
	unsigned char decrypted[MAX_MESSAGE] = {0};
	unsigned long long decrypted_len;
	
	std::string nonce = message.substr(0,crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
	std::string ciphertext = message.substr(crypto_aead_chacha20poly1305_IETF_NPUBBYTES,
			message.length()-crypto_aead_chacha20poly1305_IETF_NPUBBYTES);

	if (::crypto_aead_chacha20poly1305_ietf_decrypt(decrypted,
		&decrypted_len,
		NULL,
	        (const unsigned char *) ciphertext.data(),
		ciphertext.length(),
      		NULL,
       		0,
        	(const unsigned char *) nonce.data(),
		(const unsigned char *) key.data()) != 0)
	{
		std::cout << " Invalid Key or Password " << std::endl;
		exit(EXIT_FAILURE);
		
	} else {
		std::string tplaintext(decrypted, decrypted + decrypted_len / sizeof decrypted[0]);
		plaintext = tplaintext;
	}
	return (plaintext);
}

std::string sym_encrypt_text(std::string message, std::string key)
{
	unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
	unsigned char *ciphertext;
	unsigned long long ciphertext_len;

        ::randombytes_buf(nonce, sizeof nonce);

	ciphertext = (unsigned char *) ::malloc (crypto_aead_chacha20poly1305_IETF_ABYTES + message.length());	

	::crypto_aead_chacha20poly1305_ietf_encrypt(
				ciphertext,
				&ciphertext_len,
                (const unsigned char *) message.data(), 
                message.length(),
                NULL, 0,
                NULL, 
                nonce, 
                (const unsigned char *) key.data()
	);
	
	std::string s_nonce(nonce, nonce + sizeof nonce / sizeof nonce[0]);
	std::string s_ciphertext(ciphertext, ciphertext + ciphertext_len / sizeof ciphertext[0]);
	std::string enc = s_nonce + s_ciphertext;
	return enc;
}

std::string genkey(int s)
{
	Json::Value root;

	std::string box_kp = gen_box_keypair(s);
	std::string sign_kp = gen_sign_keypair(s);
	std::string password = gen_sym_key(s);
	std::string key = gen_sym_key(s);
	std::string box_priv = sym_encrypt_text(box_kp.substr(0,crypto_box_SECRETKEYBYTES),key);
	std::string sign_priv = sym_encrypt_text(sign_kp.substr(0,crypto_sign_SECRETKEYBYTES),key);
	std::string box_pub = box_kp.substr(crypto_box_SECRETKEYBYTES,crypto_box_PUBLICKEYBYTES);
	std::string sign_pub = sign_kp.substr(crypto_sign_SECRETKEYBYTES,crypto_sign_PUBLICKEYBYTES);
	
	std::string ek = sym_encrypt_text(key,password);
	std::string c_pub = box_pub+sign_pub;
	
	std::string enc_password	= base64_encode(reinterpret_cast<const unsigned char*>(password.c_str()), password.length());
	std::string enc_key		= base64_encode(reinterpret_cast<const unsigned char*>(ek.c_str()), ek.length());
	std::string enc_box_priv	= base64_encode(reinterpret_cast<const unsigned char*>(box_priv.c_str()), box_priv.length());
	std::string enc_sign_priv	= base64_encode(reinterpret_cast<const unsigned char*>(sign_priv.c_str()), sign_priv.length());
	std::string enc_pub		= "jaz_" + base64_encode(reinterpret_cast<const unsigned char*>(c_pub.c_str()), c_pub.length());
	
	syslog (LOG_NOTICE ,"Generated new public key %s", enc_pub.c_str());
		
	root["password"]=enc_password;
	root["key"]=enc_key;
	root["box_priv"]=enc_box_priv;
	root["sign_priv"]=enc_sign_priv;
	root["pk"]=enc_pub;
	root["hash"]=b_hash(enc_pub);

	return (root.toStyledString());
}

commands retval(std::string const& nstr)
{
	std::string str = nstr;
	str.erase(std::remove(str.begin(), str.end(), '\n'), str.end());
	str.erase(std::remove(str.begin(), str.end(), '\r'), str.end());
	if (str == "genkey") return GENKEY;
	if (str == "getheight") return GETHEIGHT;
	if (str == "getblock") return GETBLOCK;
	if (str == "havenots") return HAVENOTS;
	if (str == "sign") return SIGN;
	if (str == "newblock") return NEWBLOCK;
	if (str == "recvblock") return RECVBLOCK;
	if (str == "validate") return VALIDATE;
	if (str == "getdatakey") return GETDATAKEY;
	if (str == "getsendaddr") return GETSENDADDR;
	if (str == "getrecvaddr") return GETRECVADDR;
	if (str == "getpub") return GETPUB;
	if (str == "gethash") return GETHASH;
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

void handle_alarm(int sig)
{
    lookup_flag = true;
}

static void daemonize()
{
	pidhandle = ::open(pidfile.c_str(), O_RDWR|O_CREAT, 0600);

	if (pidhandle == -1 )
	{
		syslog(LOG_INFO, "Could not open PID lock file %s, exiting", pidfile.c_str());
		exit(EXIT_FAILURE);
	}
	if (lockf(pidhandle,F_TLOCK,0) == -1)
	{
		syslog(LOG_INFO, "Could not lock PID lock file %s, exiting", pidfile.c_str());
		exit(EXIT_FAILURE);
	}

	if (droppriv)
	{
		if (getuid() == 0)
		{
			if (setgid(groupid) != 0)
			{
				syslog (LOG_NOTICE, "Could not drop privileges: %s", strerror(errno));
				exit(EXIT_FAILURE);
			}
			if (setuid(userid) != 0)
			{
				syslog (LOG_NOTICE, "Could not drop privileges: %s", strerror(errno));
				exit(EXIT_FAILURE);
			}
		}
		syslog (LOG_NOTICE, "Dropped privileges to %d:%d",userid,groupid);
	}

	pid_t process_id = 0;
	pid_t sid = 0;
	
	process_id = fork();
	if (process_id < 0)
	{
		exit(EXIT_FAILURE);
	}
	if (process_id > 0)
	{
		syslog (LOG_NOTICE, "Child process %d", process_id);
		exit(EXIT_SUCCESS);
	}
	umask(0);
	sid = setsid();
	if(sid < 0)
	{
		exit(EXIT_FAILURE);
	}

	char str[64];
	sprintf(str,"%d\n",getpid());
	::write(pidhandle, str, ::strlen(str));
	return;
}

Json::Value parsejson(std::string sq)
{
        Json::Value tmp;
        std::stringstream ss;
        Json::CharReaderBuilder rbuilder;
        rbuilder["collectComments"] = false;
        std::string errs;
        ss << sq;
        bool isok = Json::parseFromStream(rbuilder, ss, &tmp, &errs);
        if (!isok)
        {
                tmp["ok"]=false;
                return tmp;
        } else {
                tmp["ok"]=true;
                return tmp;
        }
}

void recvblock(Json::Value rb, int s)
{
	update_db(rb);
}

void update_db(Json::Value ux)
{
	std::stringstream ss;
	sqlite3_stmt* stmt;
	char * zErrMsg = 0;
	int64_t blockid = (int64_t) ux.get("blockid",-1).asInt64();
	std::string hash(ux.get("hash","").asString());
	bool doinsert = true;
	
	if ((blockid>=0)&&(hash!=""))
	{
		ss << "SELECT validations,signatures FROM blocks WHERE blockid=" << blockid << " AND hash='" << escapestr(hash) << "'";
		std::string sql(ss.str());

		int sqlerr = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);
		if(sqlerr != SQLITE_OK)
		{
			sqlite3_finalize(stmt);
		} else {
			int ret_code = 0;
			if ((ret_code = sqlite3_step(stmt)) == SQLITE_ROW)
			{
				doinsert = false;
				int validations = (int) sqlite3_column_int(stmt, 0);
				std::string signatures = std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)));
				int ovalidations = (int) ux.get("validations",0).asInt();
				std::string osignatures(ux.get("signatures","").asString());
				if (ovalidations<validations)
				{
					std::stringstream().swap(ss); //reset
					ss << "UPDATE blocks SET validations = " << validations << ", signatures = '" << signatures << "' WHERE blockid = " << blockid << " AND hash = '" << hash << "'";
					sql = ss.str();
					int rc = sqlite3_exec(db, sql.c_str(), NULL, 0, &zErrMsg);
					if( rc != SQLITE_OK)
					{
						syslog (LOG_NOTICE, "Update block %ld failed Error: %s\n",blockid,zErrMsg);
						sqlite3_free(zErrMsg);
					} else {
						syslog (LOG_NOTICE, "Updated block %ld",blockid);
					}
				}
			}
			sqlite3_finalize(stmt);
		}
		if (doinsert)
		{
			bool isvalid = _validateblock(ux);
			if (isvalid)
			{
				std::string nonce(ux.get("nonce","").asString());
				int64_t link_blockid = (int64_t) ux.get("link_blockid",0).asInt64();
				int timestamp = (int) ux.get("timestamp",0).asInt();
				int ttl = (int) ux.get("ttl",0).asInt();
				std::string data_key(ux.get("data_key","").asString());
				std::string data(ux.get("data","").asString());
				std::string sig(ux.get("sig","").asString());
				std::string sendaddr(ux.get("sendaddr","").asString());
				std::string recvaddr(ux.get("recvaddr","").asString());
				int validations = (int) ux.get("validations",0).asInt();
				std::string signatures(ux.get("signatures","").asString());
			
				std::string sql = 
					"INSERT INTO blocks (blockid,nonce,hash,link_blockid,timestamp,ttl,data_key,data,sig,sendaddr,recvaddr,validations,signatures) VALUES ("
					+ std::to_string(blockid)				+ ",'"
					+ escapestr(nonce)					+ "','"
					+ escapestr(hash)					+ "',"
					+ std::to_string(link_blockid)	+ ","
					+ std::to_string(timestamp)				+ ","
					+ std::to_string(ttl)					+ ",'"
					+ data_key								+ "','"
					+ base64_encode(reinterpret_cast<const unsigned char*>(data.data()),data.length())	+ "','"
					+ base64_encode(reinterpret_cast<const unsigned char*>(sig.data()),sig.length())	+ "','"
					+ sendaddr								+ "','"
					+ recvaddr								+ "',"
					+ std::to_string(validations)			+ ",'"
					+ signatures							+ "');";
	
				int rc = sqlite3_exec(db, sql.c_str(), NULL, 0, &zErrMsg);
				if( rc != SQLITE_OK ){
					syslog (LOG_NOTICE, "Insert blockid %ld SQL Error: %s\n",blockid,zErrMsg);
					sqlite3_free(zErrMsg);
				} else {
					syslog (LOG_NOTICE, "Created Block %ld",blockid);
				}
			} else {
				syslog (LOG_NOTICE, "Invalid Block %ld",blockid);
			}
		}
	} else {
		syslog (LOG_NOTICE,"Error on sync %ld %s",blockid,hash.c_str());
	}
}

void sync_client(int cdx)
{
        int fd,n,sn,xn,rn;
        struct timeval timeout;
		timeout.tv_sec = 10;
		timeout.tv_usec = 0;
		int64_t o_height = 0;
		int64_t check_height = 0;

        struct sockaddr_in serv_addr;
        char buf[MAX_MESSAGE];

        if ((cdx>=0)&&(cdx<seeds.size()))
        {
                memset(buf, '0',sizeof(buf));
                if((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
                {
                        syslog(LOG_NOTICE, "Could not create client socket");
                        close(fd);
                        return;
                }
                memset(&serv_addr, '0', sizeof(serv_addr));
                serv_addr.sin_family = AF_INET;
                serv_addr.sin_port = htons(22022);
                if (inet_pton(AF_INET, seeds[cdx].ip.c_str(), &serv_addr.sin_addr)<=0)
                {
                        syslog(LOG_NOTICE, "Invalid Client IP [%d] %s", cdx, seeds[cdx].ip.c_str());
                        close(fd);
                        return;
                }
                if (connect(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
                {
                        syslog(LOG_NOTICE, "Error Client Failed [%d] %s",cdx,seeds[cdx].ip.c_str());
                        close(fd);
                        return;
                }

		/* greeting */
                while ((n = read(fd, buf, sizeof(buf)-1)) > 0)
                {
                        buf[n]='\0';
                        std::string resp(buf);
                        break;
                }

		/* getheight */
                memset(buf, '0',sizeof(buf));
                send_msg(fd,"{\"command\":\"getheight\"}");
                while ((n = read(fd, buf, sizeof(buf)-1)) > 0)
                {
                        buf[n]='\0';
                        std::string resp(buf);
                        Json::Value dr = parsejson(resp);
                        if (dr["ok"])
                        {
                                check_height = (int64_t) dr.get("blockheight",0).asInt64();
                                o_height = _getheight();
                                syslog (LOG_NOTICE, "our blockheight: %ld their blockheight: %ld",o_height,check_height);
                        }
                        break;
                }

		/* havenots */
		memset(buf, '0',sizeof(buf));
		send_msg(fd,"{\"command\":\"havenots\",\"sendaddr\":\"" + server_pubkey + "\"}");
		while ((n = read(fd, buf, sizeof(buf)-1)) > 0)
		{
			buf[n]='\0';
			std::string resp(buf);
			Json::Value dr = parsejson(resp);
			if (dr["ok"])
			{
				int nc = (int) dr.get("count",0).asInt();
				if (nc>0)
				{
				for( Json::Value::const_iterator itr = dr.begin() ; itr != dr.end() ; itr++ )
				{
					std::string titr(itr.key().asString());
					if ((titr!="ok")&&(titr!="count"))
					{
						std::string cmd = "{\"command\":\"getblock\",\"blockid\":" + titr + "}";
						memset(buf, '0',sizeof(buf));
						send_msg(fd,cmd);
						while ((sn = read(fd, buf, sizeof(buf)-1)) > 0)
						{
							buf[sn]='\0';
							std::string bd(buf);
							Json::Value dx(parsejson(buf));
							if (dx["ok"])
							{
								int64_t bid = (int64_t) dx.get("blockid",0).asInt64();
								bool isvalid = _validateblock(dx);
								if (isvalid)
								{
									syslog (LOG_NOTICE,"blk: %ld is valid",bid);
									std::string ohash(dx.get("hash","").asString());
									std::string signed_hash(sign_data(ohash));
									std::string enc_sign(base64_encode(reinterpret_cast<const unsigned char*>(signed_hash.data()), signed_hash.length()));
									syslog (LOG_NOTICE,"signed: %s",enc_sign.c_str());
									Json::Value os;
									os["blockid"]=bid;
									os["hash"]=ohash;
									os["sig"]=enc_sign;
									os["sendaddr"]=server_pubkey;
									os["command"]="sign";
									memset(buf, '0',sizeof(buf));
									send_msg(fd,os.toStyledString());
									while ((xn = read(fd, buf, sizeof(buf)-1)) > 0)
									{
										buf[xn]='\0';
										std::string re(buf);
										syslog(LOG_NOTICE,"signing response: %s",re.c_str());
										break;
									}
									
									cmd = "{\"command\":\"getblock\",\"blockid\":" + titr + "}";
									memset(buf, '0',sizeof(buf));
									send_msg(fd,cmd);
									while ((rn = read(fd, buf, sizeof(buf)-1)) > 0)
									{
										buf[rn]='\0';
										std::string rd(buf);
										Json::Value ux(parsejson(buf));
										if (ux["ok"])
										{
											update_db(ux);
										}
										break;
									}
						
									
								} else {
									syslog (LOG_NOTICE,"blk: %ld NOT VALID",bid);
								}
							} else {
								syslog (LOG_NOTICE, "invalid data (validate block)");
							}
							break;
						}
							
					}
				}
				}
				//syslog (LOG_NOTICE, "havenots: %s",rtmp.c_str());
			}
			break;
		}
		
		/* build */
		if ((o_height==0)&&(check_height>0))
		{
			for (int64_t bid = 0; bid <= check_height; bid++)
			{
				memset(buf, '0',sizeof(buf));
				send_msg(fd,"{\"command\":\"getblock\",\"blockid\":\"" + std::to_string(bid) + "\"}");
				while ((n = read(fd, buf, sizeof(buf)-1)) > 0)
				{
					buf[rn]='\0';
					std::string rd(buf);
					Json::Value ux(parsejson(buf));
					if (ux["ok"])
					{
						update_db(ux);
					}
					break;
				}
			}
		}

		/* process notifies */
		if (notify_count>0)
		{
				for (int i = 0; i < notify_count; i++)
				{
					Json::Value px = getblock(notifies[i],fd);
					px["command"] = "recvblock";
					memset(buf, '0',sizeof(buf));
					send_msg(fd,px.toStyledString());
					int xxn;
					while ((xxn = read(fd, buf, sizeof(buf)-1)) > 0)
					{
						break;
					}
				}
		}



                if (n < 0)
                {
                        syslog(LOG_NOTICE, "Read Error [%d] %s",cdx,seeds[cdx].ip.c_str());
                        close(fd);
                        return;
                }
                close(fd);
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
			if (std::find_if(seeds.begin(), seeds.end(), find_consensus(ip)) == seeds.end()) 
			{
				int cdx = seeds.size();
				seeds.push_back(consensus());
				seeds[cdx].ip = ip;
				seeds[cdx].timestamp = 0;
				seeds[cdx].blockid = 0;
				syslog (LOG_NOTICE, "Found seed %s", ip);
				syslog (LOG_NOTICE, "Seed count %lu", seeds.size());
			}
		}
	}
	notify_count = notifies.size();
	for (int i=0;i<seeds.size();i++)
	{
		sync_client(i);
	}
	for (int x=0;x<notify_count;x++)
	{
		notifies.erase(notifies.begin()+x);
	}
	notify_count = 0;
	
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
    
    ares_gethostbyname(channel, "aseed.jazmine.uno", AF_INET, dns_callback, NULL);
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

void send_msg(int s, std::string msg, ...)
{
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
	if (((int)bytes_read > 17)&&((int)bytes_read < MAX_MESSAGE)&&(users[conn_index(s)].uc_errors<max_client_errors))
	{
		Json::Value root,hashres;
		Json::CharReaderBuilder rbuilder;
		std::stringstream ss;
		ss << buf;
		rbuilder["collectComments"] = false;
		std::string errs;
		int64_t blockid;
		std::string sendaddr;
		std::string recvaddr;
		std::string data_key;
		std::string data;
		std::string hash;
		std::string sig;
		int ttl;
		hi res;
		bool suc = false;
		
		bool isok = Json::parseFromStream(rbuilder, ss, &root, &errs);
		if (!isok)
		{
				send_msg(s, json_encode("Invalid Json"));
				users[conn_index(s)].uc_errors++;
				syslog (LOG_NOTICE, "User errors on FD %d raised to %d",s,users[conn_index(s)].uc_errors);
		} else {
				std::string command = root.get("command","NOOP").asString();
				switch (retval(command))
				{
					case GENKEY: 
						send_msg(s, genkey(s));
						break;
					case GETHEIGHT:
						send_msg(s, getheight(s));
						break;
					case GETHASH:
						blockid = (int64_t) root.get("blockid",0).asInt64();
						send_msg(s, blockid_get_hash(blockid,s));
						break;
					case GETPUB:
						send_msg(s, getpub(s));
						break;
					case GETBLOCK:
						blockid = (int64_t) root.get("blockid",0).asInt64();
						send_msg(s,getblock(blockid,s));
						break;
					case VALIDATE:
						blockid = (int64_t) root.get("blockid",0).asInt64();
						send_msg(s,validateblock(blockid,s));
						break;
					case GETDATAKEY:
						data_key = root.get("data_key","").asString();
						if (data_key != "")
						{
							send_msg(s,get_data_key(data_key,s));
						} else {
							send_msg(s,json_encode("no input"));
						}
						break;
					case GETSENDADDR:
						sendaddr = root.get("sendaddr","").asString();
						if (sendaddr != "")
						{
							send_msg(s,get_sendaddr(sendaddr,s));
						} else {
							send_msg(s,json_encode("no input"));
						}
						break;
					case GETRECVADDR:
						recvaddr = root.get("recvaddr","").asString();
						if (recvaddr != "")
						{
							send_msg(s,get_recvaddr(recvaddr,s));
						} else {
							send_msg(s,json_encode("no input"));
						}
						break;
					case HAVENOTS:
						sendaddr = root.get("sendaddr","").asString();
						if (sendaddr != "")
						{
							send_msg(s,get_havenots(sendaddr,s));
						} else {
							send_msg(s,json_encode("no input"));
						}
						break;
					case SIGN:
						blockid 	= (int64_t) root.get("blockid",0).asInt64();
						hash		= root.get("hash","").asString();
						sendaddr	= root.get("sendaddr","").asString();
						sig		= root.get("sig","").asString();
						suc = _addsig(blockid,hash,sendaddr,sig);
						if (suc)
						{
							send_msg(s,json_encode("OK"));
						} else {
							send_msg(s,json_encode("FAIL"));
						}
						break;
					case RECVBLOCK:
						recvblock(root, s);
						send_msg(s,json_encode("OK"));
						break;
					case NEWBLOCK:
						sendaddr 	= root.get("sendaddr","").asString();
						recvaddr 	= root.get("recvaddr","").asString();
						data_key 	= root.get("data_key","").asString();
						data		= root.get("data","").asString();
						sig			= root.get("sig","").asString();
						ttl			= root.get("ttl",0).asInt();
						res = gen_hash(sendaddr,recvaddr,data_key,data,ttl,sig);
						hashres["blockid"] = res.blockid;
						hashres["hash"] = res.hash;
						send_msg(s, hashres.toStyledString());
						break;
					case QUIT:
						send_msg(s, json_encode("Goodbye"));
						syslog(LOG_NOTICE, "Client Disconnect (%d)",s);
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

#if defined (BSD)

void watch_loop(int kq)
{
	
    struct kevent evSet;
    struct kevent evList[32];
    int nev, i;
    struct sockaddr_in addr;
    socklen_t socklen = sizeof(addr);
    int fd;

    while (1) {
        nev = kevent(kq, NULL, 0, evList, 32, NULL);
        if (nev < 1)
        {
            syslog(LOG_NOTICE, "kevent error");
            exit(EXIT_FAILURE);
        }
        for (i=0; i<nev; i++) {
            if (evList[i].flags & EV_EOF) {
                fd = evList[i].ident;
                syslog(LOG_NOTICE, "Client Disconnect (%d)",fd);
                remove_seed(fd);
		conn_delete(fd);
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

#endif

void *domain_socket(void *)
{
	
	char buf[MAX_MESSAGE] = {0};
    size_t bytes_read;
	struct sockaddr_un addr;
	int uxfd,cl,rc,size;

	syslog(LOG_INFO, "Starting UNIX domain socket");
	
	if ((uxfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
	{
		syslog(LOG_INFO, "Could not create UNIX domain socket");
		exit(EXIT_FAILURE);
	}
	
	::memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	::strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path));
	
	size = offsetof(struct sockaddr_un, sun_path) + ::strlen(addr.sun_path);
	if (::bind(uxfd,(struct sockaddr*)&addr, size) < 0)
	{
		std::cout << "Could not bind - " << errno << std::endl;
		syslog(LOG_INFO, "Could not bind UNIX domain socket errno %d", errno);
		exit(EXIT_FAILURE);  
	}
	
	fork();

	if (::listen(uxfd,5) == -1)
	{
		syslog(LOG_INFO, "UNIX domain socket listen error");
		exit(EXIT_FAILURE);  
	}
	
	syslog(LOG_INFO, "Listening on UNIX domain socket");

	while (1)
	{
		if ((cl = ::accept(uxfd, NULL, NULL)) == -1)
		{
			syslog(LOG_INFO, "UNIX domain socket accept error");
			continue;
		}
		send_msg(cl, json_encode("welcome!"));
		syslog(LOG_NOTICE, "Client Connected on UNIX domain socket");
		conn_add(cl,"uxdom");
		
		while ((bytes_read = ::recv(cl, buf, sizeof(buf), 0))>0)
		{
			if (((int)bytes_read > 17)&&(users[conn_index(cl)].uc_errors<max_client_errors))
			{
				Json::Value root,hashres;
				Json::CharReaderBuilder rbuilder;
				int64_t blockid;
				std::string sendaddr;
				std::string recvaddr;
				std::string data_key;
				std::string data;
				std::string sig;
				std::string hash;
				int ttl;
				hi res;
				std::stringstream ss;
				ss << buf;
				rbuilder["collectComments"] = false;
				std::string errs;
				bool suc = false;
				bool isok = Json::parseFromStream(rbuilder, ss, &root, &errs);
				if (!isok)
				{
					send_msg(cl, json_encode("Invalid Json"));
					users[conn_index(cl)].uc_errors++;
					syslog (LOG_NOTICE, "User errors on FD %d raised to %d",cl,users[conn_index(cl)].uc_errors);
				} else {
					std::string command = root["command"].asString();
					int s = cl;
					switch (retval(command))
					{
					case GENKEY: 
						send_msg(s, genkey(s));
						break;
					case GETHEIGHT:
						send_msg(s, getheight(s));
						break;
                                        case GETHASH:
												blockid = (int64_t) root.get("blockid",0).asInt64();
                                                send_msg(s, blockid_get_hash(blockid,s));
                                                break;
                                        case GETPUB:
                                                send_msg(s, getpub(s));
                                                break;
					case GETBLOCK:
						blockid = (int64_t) root.get("blockid",0).asInt64();
						send_msg(s,getblock(blockid,s));
						break;
					case VALIDATE:
						blockid = (int64_t) root.get("blockid",0).asInt64();
						send_msg(s,validateblock(blockid,s));
						break;
					case GETDATAKEY:
						data_key = root.get("data_key","").asString();
						if (data_key != "")
						{
							send_msg(s,get_data_key(data_key,s));
						} else {
							send_msg(s,json_encode("no input"));
						}
						break;
					case GETSENDADDR:
						sendaddr = root.get("sendaddr","").asString();
						if (sendaddr != "")
						{
							send_msg(s,get_sendaddr(sendaddr,s));
						} else {
							send_msg(s,json_encode("no input"));
						}
						break;
					case GETRECVADDR:
						recvaddr = root.get("recvaddr","").asString();
						if (sendaddr != "")
						{
							send_msg(s,get_recvaddr(recvaddr,s));
						} else {
							send_msg(s,json_encode("no input"));
						}
						break;
                                        case HAVENOTS:
                                                sendaddr = root.get("sendaddr","").asString();
                                                if (sendaddr != "")
                                                {
                                                        send_msg(s,get_havenots(sendaddr,s));
                                                } else {
                                                        send_msg(s,json_encode("no input"));
                                                }
                                                break;
                                        case SIGN:
                                                blockid         = (int64_t) root.get("blockid",0).asInt64();
                                                hash            = root.get("hash","").asString();
                                                sendaddr        = root.get("sendaddr","").asString();
                                                sig             = root.get("sig","").asString();
                                                suc = _addsig(blockid,hash,sendaddr,sig);
                                                if (suc)
                                                {
                                                        send_msg(s,json_encode("OK"));
                                                } else {
                                                        send_msg(s,json_encode("FAIL"));
                                                }
                                                break;
					case RECVBLOCK:
						recvblock(root, s);
						send_msg(s,json_encode("OK"));
						break;
					case NEWBLOCK:
						sendaddr 	= root.get("sendaddr","").asString();
						recvaddr 	= root.get("recvaddr","").asString();
						data_key 	= root.get("data_key","").asString();
						data		= root.get("data","").asString();
						sig			= root.get("sig","").asString();
						ttl			= root.get("ttl",0).asInt();
						res = gen_hash(sendaddr,recvaddr,data_key,data,ttl,sig);
						hashres["blockid"] = res.blockid;
						hashres["hash"] = res.hash;
						send_msg(s, hashres.toStyledString());
						break;
					case QUIT:
						send_msg(s, json_encode("Goodbye"));
						syslog(LOG_NOTICE, "Client Disconnect (%d)",s);
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
				send_msg(cl, json_encode("Invalid Json"));
				users[conn_index(cl)].uc_errors++;
				syslog (LOG_NOTICE, "User errors on (%d) raised to %d",cl,users[conn_index(cl)].uc_errors);
			}
		}
		if (bytes_read == -1) {
			syslog(LOG_INFO, "UNIX domain socket read error");
			exit(EXIT_FAILURE);  
		} 
			else if (bytes_read == 0)
		{
			::close(cl);
			conn_delete(conn_index(cl));
			syslog(LOG_NOTICE, "Client disconnected from UNIX domain socket");
		}
	}
	
	return (0);
}

#if defined (BSD)

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
		exit(EXIT_FAILURE);
	}
    
    watch_loop(kq);
    
    for (;;) {}
    return (0);
}

#endif

#if defined (__linux__)

void read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	char buf[MAX_MESSAGE] = {0};
	ssize_t read;

	if(EV_ERROR & revents)
	{
		syslog(LOG_NOTICE,"read_cb event error");
		return;
	}

	read = recv(watcher->fd, buf, MAX_MESSAGE, 0);

	if(read < 0)
	{
		syslog(LOG_NOTICE,"read_cb event error");
		return;
	}

	if(read == 0)
	{
		ev_io_stop(loop,watcher);
		free(watcher);
		return;
	} else {

                Json::Value root,hashres;
                Json::CharReaderBuilder rbuilder;
                std::stringstream ss;
                ss << buf;
                rbuilder["collectComments"] = false;
                std::string errs;
                int64_t blockid;
                std::string sendaddr;
                std::string recvaddr;
                std::string data_key;
                std::string data;
                std::string sig;
		std::string hash;
                int ttl;
                hi res;
		bool suc = false;

		int s = watcher->fd;

//send_msg(s,ss.str());

                bool isok = Json::parseFromStream(rbuilder, ss, &root, &errs);
                if (!isok)
                {
                                send_msg(s, json_encode("Invalid Json"));
                                users[conn_index(s)].uc_errors++;
                                syslog (LOG_NOTICE, "User errors on FD %d raised to %d",s,users[conn_index(s)].uc_errors);
                } else {
                                std::string command = root.get("command","NOOP").asString();
                                switch (retval(command))
                                {
                                        case GENKEY:
                                                send_msg(s, genkey(s));
                                                break;
                                        case GETHEIGHT:
                                                send_msg(s, getheight(s));
                                                break;
                                        case GETHASH:
                                                blockid = (int64_t) root.get("blockid",0).asInt64();
                                                send_msg(s, blockid_get_hash(blockid,s));
                                                break;
                                        case GETPUB:
                                                send_msg(s, getpub(s));
                                                break;
                                        case GETBLOCK:
                                                blockid = (int64_t) root.get("blockid",0).asInt64();
                                                send_msg(s,getblock(blockid,s));
                                                break;
                                        case VALIDATE:
                                                blockid = (int64_t) root.get("blockid",0).asInt64();
                                                send_msg(s,validateblock(blockid,s));
                                                break;
                                        case GETDATAKEY:
                                                data_key = root.get("data_key","").asString();
                                                if (data_key != "")
                                                {
                                                        send_msg(s,get_data_key(data_key,s));
                                                } else {
                                                        send_msg(s,json_encode("no input"));
                                                }
                                                break;
                                        case GETSENDADDR:
                                                sendaddr = root.get("sendaddr","").asString();
                                                if (sendaddr != "")
                                                {
                                                        send_msg(s,get_sendaddr(sendaddr,s));
                                                } else {
                                                        send_msg(s,json_encode("no input"));
                                                }
                                                break;
                                        case GETRECVADDR:
                                                recvaddr = root.get("recvaddr","").asString();
                                                if (recvaddr != "")
                                                {
                                                        send_msg(s,get_recvaddr(recvaddr,s));
                                                } else {
                                                        send_msg(s,json_encode("no input"));
                                                }
                                                break;
                                        case HAVENOTS:
                                                sendaddr = root.get("sendaddr","").asString();
                                                if (sendaddr != "")
                                                {
                                                        send_msg(s,get_havenots(sendaddr,s));
                                                } else {
                                                        send_msg(s,json_encode("no input"));
                                                }
                                                break;
                                        case SIGN:
                                                blockid         = (int64_t) root.get("blockid",0).asInt64();
                                                hash            = root.get("hash","").asString();
                                                sendaddr        = root.get("sendaddr","").asString();
                                                sig             = root.get("sig","").asString();
                                                suc = _addsig(blockid,hash,sendaddr,sig);
                                                if (suc)
                                                {
                                                        send_msg(s,json_encode("OK"));
                                                } else {
                                                        send_msg(s,json_encode("FAIL"));
                                                }
                                                break;
					case RECVBLOCK:
						recvblock(root, s);
						send_msg(s,json_encode("OK"));
						break;

                                        case NEWBLOCK:
                                                sendaddr        = root.get("sendaddr","").asString();
                                                recvaddr        = root.get("recvaddr","").asString();
                                                data_key        = root.get("data_key","").asString();
                                                data            = root.get("data","").asString();
                                                sig                     = root.get("sig","").asString();
                                                ttl                     = root.get("ttl",0).asInt();
                                                res = gen_hash(sendaddr,recvaddr,data_key,data,ttl,sig);
                                                hashres["blockid"] = res.blockid;
                                                hashres["hash"] = res.hash;
                                                send_msg(s, hashres.toStyledString());
                                                break;
                                        case QUIT:
                                                send_msg(s, json_encode("Goodbye"));
                                                syslog(LOG_NOTICE, "Client Disconnect (%d)",s);
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
  

	}

	bzero(buf, read);
	return;
}


void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);
	int client_sd;
	struct ev_io *w_client = (struct ev_io*) malloc (sizeof(struct ev_io));

	if(EV_ERROR & revents)
	{
		syslog(LOG_NOTICE,"Event Error");
		return;
	}
	
	client_sd = accept(watcher->fd, (struct sockaddr *)&client_addr, &client_len);

	syslog(LOG_NOTICE,"Client Connect [%d]",client_sd);

	if (client_sd < 0)
	{
		syslog(LOG_NOTICE,"Client Accept Error");
		return;
	}
	std::string clientip(inet_ntoa(client_addr.sin_addr));
	syslog(LOG_NOTICE, "Client Connected [%d] %s",client_sd,clientip.c_str());
	conn_add(client_sd,clientip);
	send_msg(client_sd, json_encode("welcome!"));
	if (clients.size()<NUSERS)
	{
		if (std::find(clients.begin(), clients.end(), clientip) == clients.end())
		{
			clients.push_back(clientip);
			syslog (LOG_NOTICE, "Added client %s", clientip.c_str());
			syslog (LOG_NOTICE, "Connected clients count %lu", clients.size());
		}
	}

	ev_io_init(w_client, read_cb, client_sd, EV_READ);
	ev_io_start(loop, w_client);
}

void *start_server(void *)
{
	int xp, flags, s;
	struct sockaddr_in sa;
	struct ev_loop *loop = ev_default_loop(0);
	struct ev_io w_accept;

	srv = ::socket(PF_INET, SOCK_STREAM, 0);
	bzero(&sa,sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_ANY); //INADDR_LOOPBACK
	sa.sin_port = htons( srv_port );
    
	if (::bind(srv, (struct sockaddr *)&sa, sizeof(sa))<0)
	{
		syslog(LOG_NOTICE, "Error bind");
	}

	flags = fcntl (srv, F_GETFL, 0);
	if (flags < 0) flags = 0;
	s = fcntl (srv, F_SETFL, flags | O_NONBLOCK);

	fork();
	
	::listen(srv, SOMAXCONN);

	syslog(LOG_NOTICE, "Started Listening on %s:%d",inet_ntoa(sa.sin_addr),ntohs(sa.sin_port));

	ev_io_init(&w_accept, accept_cb, srv, EV_READ);
	ev_io_start(loop, &w_accept);
	while (1)
	{
		ev_loop(loop, 0);
	}
}

#endif

     
int main(int argc, char* argv[])
{
	pthread_t srv_thread_id, alarm_thread_id, uxdom_thread_id;
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

	std::cout << "\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n"
	<< "jazmine_a blockchain server\nCopyright 2018 Waitman Gobble <waitman@tradetal.com>\n"
	<< "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n";

	setlogmask (LOG_UPTO (LOG_NOTICE));
	openlog ("jazmine_a", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
	syslog(LOG_NOTICE, "Started by uid %d", getuid());
	
	Json::Value root;
	std::ifstream file(config_file);
	syslog(LOG_NOTICE, "Config file %s", config_file.c_str());
	if (file.good())
	{
		syslog(LOG_NOTICE, "Config file exists");
		file >> root;
	} else {
		syslog(LOG_NOTICE, "Config file does not exist, using defaults");
	}
	std::string dbfile = root.get("dbfile","jazmine_a.db").asString();
	syslog(LOG_NOTICE, "DB File %s", dbfile.c_str());
	pidfile = root.get("pidfile","/var/run/jazmine_a.pid").asString();
	syslog(LOG_NOTICE, "pid File %s", pidfile.c_str());
	socket_path = root.get("sockpath","/tmp/jazmine_a.sock").asString();
	syslog(LOG_NOTICE, "socket File %s", socket_path.c_str());
	::unlink(socket_path.c_str());
	std::string keyfile = root.get("keyfile","jazmine_a.keys.json").asString();
	std::string tmppass = "";
	std::string tmpkey = "";
	if (keyfile!="")
	{
		Json::Value kr;
		std::ifstream kf(keyfile);
		if (kf.good())
		{
			kf >> kr;
			tmppass = kr.get("password","").asString();
			if (tmppass!="")
			{
				server_pubkey = kr.get("pk","").asString();
				server_pk = kr.get("sign_priv","").asString();
				tmpkey = kr.get("key","").asString();
			}
		}
	}
	if (server_pubkey!="")
	{
		syslog(LOG_NOTICE,"Server Public Key %s",server_pubkey.c_str());
		std::cout << "Server Public Key: " << server_pubkey << std::endl;
	}
	bool is_fine = false;
	if (server_pk!="")
	{
		if (tmppass!="")
		{

			std::string decpass = base64_decode(tmppass);
			std::string decpriv = base64_decode(server_pk);
			std::string deckey = base64_decode(tmpkey);
			std::string server_key = sym_decrypt_text(deckey,decpass);
			server_pk = sym_decrypt_text(decpriv,server_key);
			if (server_pk.length()>0)
			{
				is_fine=true;
			}
			server_key = "";
			deckey = "";
			decpriv = "";
			decpass = "";
		}
	}
	tmppass = "";
	tmpkey = "";
	if (!is_fine)
	{
		std::string pks = genkey(-1);
		std::cout << std::endl << "Generated server keys, save the JSON below to jazmine_a.keys.json" << std::endl << std::endl << pks << std::endl << std::endl;
		exit(EXIT_FAILURE);
	}
	
	userid = root.get("userid",65534).asInt();
	groupid = root.get("groupid",65534).asInt();
	droppriv = root.get("droppriv",true).asBool();
	srv_port = root.get("srv_port",22022).asInt();
	dns_ttl = root.get("dns_ttl",60).asInt();
	if (dns_ttl<60) dns_ttl = 60;
	syslog(LOG_NOTICE, "DNS TTL %d", dns_ttl);
	max_client_errors = root.get("max_client_errors",4).asInt();
	syslog(LOG_NOTICE, "Max Client Errors %d", max_client_errors);
	
	daemon = root.get("daemon",true).asBool();

	std::signal(SIGINT, termHandler);
	std::signal(SIGTERM, termHandler);
	
	if(sqlite3_open(dbfile.c_str(), &db) != SQLITE_OK) {
		syslog(LOG_NOTICE, "Error: Cannot open database: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }
    
    std::cout << "Checking database" << std::endl;
    
	std::string sql("SELECT MAX(blockid) FROM blocks");
	if(sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL) != SQLITE_OK)
	{
		std::string createdb("CREATE TABLE blocks (blockid INTEGER, nonce TEXT, hash TEXT, link_blockid INTEGER, timestamp INTEGER, ttl INTEGER, data_key TEXT, data TEXT, sig TEXT, sendaddr TEXT, recvaddr TEXT,validations INTEGER,signatures TEXT);");
		if(sqlite3_prepare_v2(db, createdb.c_str(), -1, &stmt, NULL) != SQLITE_OK)
		{
			sqlite3_close(db);
			sqlite3_finalize(stmt);
			syslog(LOG_NOTICE, "Could not create database: %s", sqlite3_errmsg(db));
			return 1;
		}
		std::cout << "Created new database.\n";
		syslog(LOG_NOTICE, "Database tables created");
	}
	int ret_code = 0;
    if ((ret_code = sqlite3_step(stmt)) == SQLITE_ROW) {
		int64_t blockheight = sqlite3_column_int(stmt, 0);
		syslog(LOG_NOTICE, "Blockheight: %lu",blockheight);
		std::cout << "Blockheight: " << blockheight << std::endl;
    }
	sqlite3_finalize(stmt);

	std::cout << "Launching UNIX domain socket server thread" << std::endl;
	pthread_create(&uxdom_thread_id, NULL, domain_socket, (void *) NULL);
	sleep(2); //warmup
	std::cout << "Launching tcp server thread" << std::endl;
	pthread_create(&srv_thread_id, NULL, start_server, (void *) NULL);
	sleep(2); //warmup

	if (daemon)
	{
		std::cout << "Forking to daemon" << std::endl;
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
