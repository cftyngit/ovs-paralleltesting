#ifndef __OVSPTD_BUFFER_H__
#define __OVSPTD_BUFFER_H__

#include <map>
#include <sstream>
#include <vector>
#include <utility>
#include <string>

#include "../commom.h"

using std::vector;
using std::stringstream;
using std::map;
using std::pair;
using std::string;
using std::istream;
using std::ostream;

class all_compares;

struct compare_key
{
	my_ip_type	rmhost_ip;
	UINT16	rmhost_port;
	UINT8	proto;
	bool operator< ( const compare_key &right ) const;
};

struct compare_info
{
	UINT8 proto;
	const host_info rmhost;
	host_info target;
	host_info mirror;
};

class compare_obj
{
	compare_info _info;
	pair<stringstream, stringstream> _buffer;
	friend all_compares;
public:
	compare_obj(host_info rmhost_info, UINT8 proto)
		:_info({proto, rmhost_info,})
	{}
	compare_obj(const compare_obj& c_obj)
		:_info(c_obj._info)
	{}
	istream& target_data(){return _buffer.first;}
	istream& mirror_data(){return _buffer.second;}
	compare_info get_info(){return _info;}
};

class all_compares
{
	map<compare_key, compare_obj> _all_data;
public:
	vector<compare_info> query_all_compares();
	compare_obj* get_compare(compare_key key);
	int add_data(string data, connection_info info);
	int add_data(const char* data, int size, connection_info info);
};

#endif
