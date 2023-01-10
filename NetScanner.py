#!/usr/bin/env python3
import re
import nmap
import time
import json
import socket
import platform
import netifaces
from re import search
from datetime import datetime
import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether
from getmac import get_mac_address as gma
from concurrent.futures import ThreadPoolExecutor

# Максимальное время сканирования сети. Если за timeout не найдено ни одного устройства, считается, что к сети никто не подключён.
timeout = time.time() + 60*1

# Регулярное выражение для парсинга ipV4
pattern_1 = re.compile('^[\d]{1,3}[\.][\d]{1,3}[\.][\d]{1,3}[\.][\d]{1,3}[\/][\d]{1,3}$|^[\d]{1,3}[\.][\d]{1,3}[\.][\d]{1,3}[\.][\d]{1,3}$')
pattern_2 = re.compile('^[\d]{1,3}[\.][\d]{1,3}[\.][\d]{1,3}[\.][\d]{1,3}$')
pattern_3 = re.compile('^[\d]{1,3}[\.][\d]{1,3}[\.][\d]{1,3}[\.]')

#List-LocalHost, List-Known-Adapter
localhost_list = ["localhost", "127.0.0.1"]
localhost_list.append(socket.gethostbyname(socket.gethostname()))
known_adapter = []
port_range = []

def readPortsConfige():
    port_range = []
    try:
        file = open("ports.txt", "r")
        lines = file.readlines()
        for line in lines:
            port_range.append(line.strip())
        file.close()
    except:
        port_range = ["20", "21", "22", "23", "25", "53", "67", "69", "80", "123", "135", "137", "139", "161", "389", "443", "445", "500", "761", "993", "995", "1194", "1337", "1433", "1434", "1701", "1723", "3000", "3389", "3391", "5432", "5601", "7601", "8080"]
    return port_range

def readKnownAdapter():
    temp = []
    try:
        file = open("knownAdapter.txt", "r")
        lines = file.readlines()
        for line in lines:
            temp.append(line.strip())
        file.close()
    except:
        temp = ["8.8.8.8", "0.0.0.0"]
    return temp

def checkingSubnet(target):
    myNet = (socket.gethostbyname(socket.gethostname()))

    temp = pattern_3.findall(target)[0]
    myNet = pattern_3.findall(myNet)[0]

    if myNet == temp:
        return True
    else:
        return False

def getfqdn(ip):
    return ip, socket.getfqdn(ip)

def checkDNSname(clients_list):
    list_of_ips = []
    for element in clients_list:
        list_of_ips.append(element["ip"])

    results = dict()
    with ThreadPoolExecutor() as executor:
        for future in [executor.submit(getfqdn, ip) for ip in set(list_of_ips)]:
            ip, fqdn = future.result()
            results[ip] = fqdn

    for el in clients_list:
        name = results[el["ip"]]

        if name == el["ip"]:
            el["hostname"] = ""
        else:
            el["hostname"] = results[el["ip"]]
            
    return clients_list

def nmap_os_check(clients_list, detailedScan, event):
    nm = nmap.PortScanner()
    interval = "-O"

    if(detailedScan):
        interval += " --host-timeout 3m"
    else:
        interval += " --host-timeout 1m"
        interval += " --osscan-limit --osscan-guess"

    for client in clients_list:
        try:
            if event.is_set():
                return clients_list

            ip = client["ip"]
            if ip == "localhost":
                ip = "127.0.0.1"
            if len(ip) > 19:
                client["os"] = ""
                continue
            result = nm.scan(hosts=ip, arguments=interval)
            OS = result["scan"][ip]['osmatch'][0]['name']
            client["os"] = OS
        except:
            client["os"] = ""
    return clients_list

def nmap_ports_check(clients_list, detailedScan, event):
    port_range = readPortsConfige()
    nm = nmap.PortScanner()

    if(detailedScan):
        string_parametres = " --host-timeout 3m"
        string_parametres += " --min-parallelism 10"
    else:
        string_parametres = " --host-timeout 1m"
        string_parametres += " --min-parallelism 10"

    for client in clients_list:
        try:
            if event.is_set():
                return clients_list

            ip = client["ip"]
            if ip == "localhost":
                ip = "127.0.0.1"
            if len(ip) > 16:
                continue

            interval = "-p "
            for i in port_range:
                interval += i
                interval += ","
            interval = interval[:-1]
            interval += string_parametres

            nm.scan(hosts=ip, arguments=interval)
            ports = list(nm[ip]['tcp'].keys())
            open_ports = []
            for i in ports:
                res = nm[ip]['tcp'][i]["state"]
                if res == "open":
                    open_ports.append(str(i))
            client["ports"] = open_ports
        except:
            client["ports"] = ["Exception when scanning"]
    return clients_list

def scanning(ip):
    clients_list = []
    flag = checkingSubnet(ip)

    if(flag):
        broadcast_request = Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip)
        answered_list = scapy.srp(broadcast_request, timeout=3, verbose=False)[0]

        if answered_list is not None:
            for element in answered_list:
                client = {"ip": element[1].psrc, "mac": element[1].hwsrc, "hostname": "", "os": "", "ports": [], "tracert": [], "dateTime": datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                clients_list.append(client)
    else:
        icmp_request_broadcast = scapy.Ether() / scapy.IP(dst=ip) / scapy.ICMP()
        answered_list = scapy.srp(icmp_request_broadcast, timeout=3, verbose=False)[0]

        if answered_list is not None:
            for element in answered_list:
                client = {"ip": element[1]["IP"].src, "mac": "", "hostname": "", "os": "", "ports": [], "tracert": [], "dateTime": datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                clients_list.append(client)
    return clients_list

def traceroute_check(clients_list, event):
    for client in clients_list:
        if len(client["ip"]) > 19:
            continue
        route = []
        try:
            if event.is_set():
                return clients_list

            target = client["ip"]
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
            client["tracert"] = route
        except:
            client["tracert"] = ["Undefined route"]
    return clients_list

#Check-Network-Interfaces
def get_all_ipv4_addresses():
    ips = []
    for iface in netifaces.interfaces():
        for link in netifaces.ifaddresses(iface).get(netifaces.AF_INET, []):
            ip = link.get('addr', None)
            if ip:
                ips.append(ip)
    return ips

def networkScan(target):
    scan_result = []
    known_adapter = readKnownAdapter()

    parsResult = pattern_1.findall(target)
    if parsResult == []:
        return {"resultCode": 1, "errorMessage": "Incorrect ipV4 address in networkScan()."}

    if target in localhost_list:
        scan_result.append(
            {"ip": socket.gethostbyname(socket.gethostname()), "mac": gma(), "hostname": "", "os": platform.system(), "ports": [], "tracert": [], "dateTime": datetime.now().strftime('%Y-%m-%d %H:%M:%S')})
    elif target in known_adapter:
        scan_result.append({"ip": target, "mac": "0.0.0.0", "hostname": "", "os": "", "ports": [], "tracert": [], "dateTime": datetime.now().strftime('%Y-%m-%d %H:%M:%S')})
    else:
        scan_result = scanning(target)

    answer = checkDNSname(scan_result)
    return {"resultCode": 0, "devices": answer}

def deepScan(target, osFlag, portsFlag, tracertFlag, detailedScan, data, event):
    scan_hosts_list = json.loads(target)
    scan_hosts_list = scan_hosts_list["target"]

    if (osFlag):
        scan_result = nmap_os_check(scan_hosts_list, detailedScan, event)
    else:
        scan_result = scan_hosts_list

    if (portsFlag):
        temp_result = nmap_ports_check(scan_result, detailedScan, event)
    else:
        temp_result = scan_result

    if (tracertFlag):
        scan_result = traceroute_check(temp_result, event)
    else:
        scan_result = temp_result

    data.append({"resultCode": 0, "devices": scan_result})

def scanByTable(list_ip):
    ans_list = []
    unans_list = []
    unique = {each['ip']: each for each in list_ip}.values()

    localhost = []
    temp_arp = []
    temp_icmp = []

    for element in unique:
        parsResult = pattern_2.findall(element["ip"])
        if parsResult == []:
            checkLocalHost = False
            for elem in localhost_list:
                if search(elem, element["ip"]):
                    checkLocalHost = True

            if checkLocalHost == True:
                element["ip"] = socket.gethostbyname(socket.gethostname())
            else:
                return {"resultCode": 1, "errorMessage": "Incorrect ipV4 address in scanByTable()."}

        if element["ip"] in localhost_list:
            localhost.append({"ip": element["ip"], "mac": gma()})
        else:
            if checkingSubnet(element["ip"]) == True:
                temp_arp.append(element["ip"])
            else:
                temp_icmp.append(element["ip"])

#В этом месте вызывается warning broadcast. Можно temp поделить на 2 массива и для них по разному проверять доступность
    broadcast_request = Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=temp_arp)
    answered_arp_list, unanswered_arp_list = scapy.srp(broadcast_request, timeout=3, verbose=False)

    icmp_request_broadcast = scapy.Ether() / scapy.IP(dst=temp_icmp) / scapy.ICMP()
    answered_icmp_list, unanswered_icmp_list = scapy.srp(icmp_request_broadcast, timeout=3, verbose=False)

    for received in answered_arp_list:
        ans_list.append({"ip": received[1].psrc})

    for received in answered_icmp_list:
        ans_list.append({"ip": received[1]["IP"].src})

    for received in unanswered_arp_list:
        unans_list.append({"ip": received.pdst})

    for received in unanswered_icmp_list:
        unans_list.append({"ip": received["IP"].dst})

    for element in localhost:
        ans_list.append({"ip": element["ip"]})

    return {"resultCode": 0, "ans_list": ans_list, "unans_list": unans_list}


def prepareIP(ip):
    scheme = re.compile('^[\d]{1,3}[\.][\d]{1,3}[\.][\d]{1,3}[\.]')
    constantIP = scheme.findall(ip)[0]

    pattern = re.compile('[\d]{1,3}\-[\d]{1,3}$')
    result = pattern.findall(ip)
    start, finish = result[0].split("-")

    if int(start) >= int(finish):
        return 1
    else:
        client_list = []
        for i in range(int(start), int(finish) + 1):
            temp = constantIP + str(i)
            client_list.append({"ip": temp})
        return client_list

def scanByRange(list_ip):
    unique = {each['ip']: each for each in list_ip}.values()
    known_adapter = readKnownAdapter()
    temp = []
    localhost = []
    clients_list = []

    for element in unique:
        parsResult = pattern_2.findall(element["ip"])
        if parsResult == []:
            return {"resultCode": 1, "errorMessage": "Incorrect ipV4 address in scanByRange()."}
        if element["ip"] in localhost_list:
            localhost.append({"ip": socket.gethostbyname(socket.gethostname()), "mac": gma()})
        elif element["ip"] in known_adapter:
            localhost.append({"ip": element["ip"], "mac": "inListKnownAdapter"})
        else:
            temp.append(element["ip"])

    if temp != []:
        flag = checkingSubnet(temp[0])
    else:
        flag = False

    if (flag):
        broadcast_request = Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=temp)
        answered_list = scapy.srp(broadcast_request, timeout=3, verbose=False)[0]

        if answered_list is not None:
            for element in answered_list:
                client = {"ip": element[1].psrc, "mac": element[1].hwsrc}
                clients_list.append(client)
    else:
        icmp_request_broadcast = scapy.Ether() / scapy.IP(dst=temp) / scapy.ICMP()
        answered_list = scapy.srp(icmp_request_broadcast, timeout=3, verbose=False)[0]

        if answered_list is not None:
            for element in answered_list:
                client = {"ip": element[1]["IP"].src, "mac": element[1]["Ethernet"].src}
                clients_list.append(client)

    for element in localhost:
        clients_list.append(element)
    return json.dumps({"resultCode": 0, "ans_list": clients_list})

def alternativeScan(ip_list):
    result = json.loads(scanByRange(ip_list))['ans_list']
    answer_list = []
    for element in result:
        answer_list.append({"ip": element["ip"], "mac": element["mac"], "hostname": "", "os": "", "ports": [], "tracert": [],
                            "dateTime": datetime.now().strftime('%Y-%m-%d %H:%M:%S')})
    answer = checkDNSname(answer_list)
    return {"resultCode": 0, "devices": answer}