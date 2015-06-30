#include "ovsptd_buffer.h"
#include <cstdio>
int all_compares::add_data ( string data, connection_info info )
{
	const compare_key _key = {.rmhost_ip = info.ip, .rmhost_port = info.port, .proto = info.proto};
	map<compare_key, compare_obj>::iterator it;

	if(!data.size() || (info.host_type != HOST_TYPE_TARGET && info.host_type != HOST_TYPE_MIRROR))
		return -1;

	it = _all_data.find(_key);
	if (it == _all_data.end())
	{//Can't find compare_obj in map, we need to insert a new compare_obj into map
		host_info rm_info;
		rm_info.ip = _key.rmhost_ip;
		rm_info.port_no = _key.rmhost_port;
		it = _all_data.insert(pair<compare_key, compare_obj>(_key, compare_obj(rm_info, _key.proto))).first;
	}
	ostream& result_buffer = info.host_type == HOST_TYPE_TARGET ? it->second._buffer.first : it->second._buffer.second;
	result_buffer.write(data.c_str(), data.size());
	return 0;
}

int all_compares::add_data ( const char* data, int size, connection_info info )
{
	const compare_key _key = {.rmhost_ip = info.ip, .rmhost_port = info.port, .proto = info.proto};
	map<compare_key, compare_obj>::iterator it;

	if(!size || (info.host_type != HOST_TYPE_TARGET && info.host_type != HOST_TYPE_MIRROR))
		return -1;

	it = _all_data.find(_key);
	if (it == _all_data.end())
	{//Can't find compare_obj in map, we need to insert a new compare_obj into map
		host_info rm_info;
		rm_info.ip = _key.rmhost_ip;
		rm_info.port_no = _key.rmhost_port;
		it = _all_data.insert(pair<compare_key, compare_obj>(_key, compare_obj(rm_info, _key.proto))).first;
	}
	ostream& result_buffer = info.host_type == HOST_TYPE_TARGET ? it->second._buffer.first : it->second._buffer.second;
	result_buffer.write(data, size);
	printf("[insert data] host: %d, size: %d\n", info.host_type, size);
	return 0;
}

bool compare_key::operator< ( const compare_key &right ) const
{
	if(rmhost_ip.i != right.rmhost_ip.i)
		return rmhost_ip.i < right.rmhost_ip.i;

	if(rmhost_port != right.rmhost_port)
		return rmhost_port < right.rmhost_port;

	return proto < right.proto;
}

vector< compare_info > all_compares::query_all_compares()
{
	vector<compare_info> ret;
	for (map<compare_key, compare_obj>::iterator it = _all_data.begin(); it != _all_data.end(); ++it)
		ret.push_back(it->second.get_info());

	return ret;
}

compare_obj* all_compares::get_compare ( compare_key key )
{
	map<compare_key, compare_obj>::iterator it;
	it = _all_data.find(key);
	if (it == _all_data.end())
		return NULL;

	return &it->second;
}
