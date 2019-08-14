import zeroconf
import json
import sys

svc_list = []
hostname = {}

services = zeroconf.search(domain="local")
if len(services) is 0:
    print "No device found"
    sys.exit(0)

for host in services.items():
    if str(host[1]['hostname']) not in hostname:
        data = {}
        extra = {}
        port = []
        serv_type = []
        data['hostname'] =  str(host[1]['hostname'])
        data['name'] = str(host[0][0])
        data['address'] =  str(host[1]['address'])
        extra['type'] = str(host[0][1])
        extra['port'] = str(host[1]['port'])
        data['extra'] = extra
        hostname[str(host[1]['hostname'])] = data
    else:
        extra = hostname[str(host[1]['hostname'])]['extra']
        extra['type'] += ", " + str(host[0][1])
        extra['port'] += ", " + str(host[1]['port'])
        hostname[str(host[1]['hostname'])]['extra'] = extra

for key, value in hostname.items():
    svc_list.append(value)

out_data = json.dumps(svc_list, indent=True)
print out_data
