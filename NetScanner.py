#!/usr/bin/env python3
import nmap
import time
import json
import argparse
import scapy.all as scapy
from scapy.config import conf
from pymongo import MongoClient

client = MongoClient('localhost', 27017)
db = client['IP_MAC_LINE']
deviceNow = db['deviceNow']
deviceOld = db['deviceOld']
deviceAllTime = db['deviceAllTime']

new_device = []
old_device = []
Connect_device = []
Disconnect_device = []

scan_result = []
timeout = time.time() + 60*1

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP/IP-range.")
    parser.add_argument("-o", "--OS", dest="os_param", action="store_true", help="Check OS on device.")
    parser.add_argument("-s", "--special", dest="special_param", action="store_true", help="Send results in special form to server.")
    parser.add_argument("-p", "--port", dest="port_param", action="store_true", help="Check enable port in device.")
    parser.add_argument("-tr", "--traceroute", dest="traceroute_param", action="store_true", help="Check path to device.")
    options = parser.parse_args()
    return options

def nmap_os_check(clients_list):
    nm = nmap.PortScanner()
    for client in clients_list:
        try:
            ip = client["IP"]
            result = nm.scan(hosts=ip, arguments='-O --host-timeout 1m')
            OS = result["scan"][ip]['osmatch'][0]['name']
            client["OS"] = OS
        except:
            client["OS"] = "Unknown"
    return clients_list

def nmap_ports_check(clients_list):
    nm = nmap.PortScanner()
    for client in clients_list:
        try:
            ip = client["IP"]
            #interval = "1-65535"
            #nm.scan(ip, interval)
            nm.scan(hosts=ip, arguments='--host-timeout 1m')
            ports = list(nm[ip]['tcp'].keys())
            client["Ports"] = ports
        except:
            client["Ports"] = "Unknown"
    return clients_list

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client = {"IP": element[1].psrc, "MAC": element[1].hwsrc, "OS": "Unknown", "Ports": [], "Traceroute": []}
        clients_list.append(client)
    return clients_list

def get_data(collection):
    results = list(collection.find({}))
    return results

def insert_data_in_BD(collection, insert_file):
    if insert_file != []:
        collection.insert_many(insert_file)

def prepare_collection_in_BD(mainCollection, oldCollection):
    data = get_data(mainCollection)
    oldCollection.delete_many({})
    mainCollection.delete_many({})
    if data != []:
        oldCollection.insert_many(data)

def save_device_in_history(collection, Connect_device, Disconnect_device):
    dateTime = time.ctime()

    if Connect_device != []:
        for el in Connect_device:
            el["time"] = dateTime
            el["status"] = "connect"
        collection.insert_many(Connect_device)

    if Disconnect_device != []:
        for el in Disconnect_device:
            el["time"] = dateTime
            el["status"] = "disconnect"
        collection.insert_many(Disconnect_device)

def check_device_in_network(data_now, data_old):
    for element in data_now:
        new_device.append(element["MAC"])

    for element in data_old:
        old_device.append(element["MAC"])

    for element in data_now:
        if element["MAC"] not in old_device:
            Connect_device.append({"IP": element["IP"], "MAC": element["MAC"]})

    for element in data_old:
        if element["MAC"] not in new_device:
            Disconnect_device.append({"IP": element["IP"], "MAC": element["MAC"]})

def traceroute_check(clients_list):
    for client in clients_list:
        route = []
        try:
            target = client["IP"]
            TTL = 32
            packet = scapy.IP(dst=target) / scapy.ICMP()
            for i in range(TTL):
                packet["IP"].ttl = i + 1
                ans = scapy.sr1(packet, timeout=2, verbose=False)
                try:
                    if ans is None:
                        route.append("***")
                        continue
                    if ans["ICMP"].type != 0:
                        route.append(ans["IP"].src)
                    else:
                        route.append(ans["IP"].src)
                        break
                except:
                    pass
            client["Traceroute"] = route
        except:
            pass
    return clients_list

def print_traceroute_path(results_list):
    print("\n................Трассировка сетевого маршрута................")
    for client in results_list:
        print("Трассировка для " + client["IP"])
        counter = 1
        for addr in client["Traceroute"]:
            print(counter, end ='')
            print(". " + addr)
            counter += 1

def print_result(results_list, Connect_device, Disconnect_device):
    if (options.special_param):
        data = [{"ResultCode": 0}, {
            "Online": results_list,
            "Connected": Connect_device,
            "Disconnected": Disconnect_device }]
        temp = json.dumps(data)
        print(temp)
    else:
        print("\nСписок обнаруженных устройств: ")
        print("IP\t\t\tMAC Address\t\t\tOS\t\t    Ports\t\t\n.........................................................................................")
        for client in results_list:
            try:
                print(client["IP"] + "\t\t" + client["MAC"] + "\t" + client["OS"] + "\t" + "   ", end ='')
                print(client["Ports"])
            except:
                pass
        print("\nСписок подключившихся к сети устройств: ")

        for element in Connect_device:
            print(element["IP"] + "\t\t", end='')
            print(element["MAC"])

        print("\nСписок отключившихся от сети устройств: ")
        for element in Disconnect_device:
            print(element["IP"] + "\t\t", end='')
            print(element["MAC"])

        if (options.traceroute_param):
            print_traceroute_path(results_list)

options = get_arguments()

if(options.target.find("127.0.0.1") != -1):
    ip = scapy.get_if_addr(conf.iface)
    options.target = ip

while scan_result == []:
    scan_hosts_list = scan(options.target)
    scan_result = scan_hosts_list
    if time.time() > timeout:
        break

if (options.os_param):
    scan_result = nmap_os_check(scan_hosts_list)

if (options.port_param):
    temp_result = nmap_ports_check(scan_result)
else:
    temp_result = scan_result

if (options.traceroute_param):
    scan_result = traceroute_check(temp_result)
else:
    scan_result = temp_result

prepare_collection_in_BD(deviceNow, deviceOld)
insert_data_in_BD(deviceNow, scan_result)

data_now = get_data(deviceNow)
data_old = get_data(deviceOld)
check_device_in_network(data_now, data_old)

try:
    for element in scan_result:
        if '_id' in element:
            del element['_id']
except:
    pass

save_device_in_history(deviceAllTime, Connect_device, Disconnect_device)
print_result(scan_result, Connect_device, Disconnect_device)