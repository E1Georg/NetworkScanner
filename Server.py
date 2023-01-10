#!/usr/bin/env python3
from flask import Flask, request
from flask_restful import Api
import json
import re
from NetScanner import networkScan, deepScan, scanByTable, prepareIP, alternativeScan, get_all_ipv4_addresses

from datetime import datetime
import platform
from threading import Thread, Event
from getmac import get_mac_address as gma

app = Flask(__name__)
api = Api(app)
threading_pointer = {}

@app.route('/metrix', methods=['GET'])
def metrix():
    return json.dumps({"resultCode": 0, "localhostInterfaces": [{"ip": get_all_ipv4_addresses(), "mac": gma(), "os": platform.system(), "dateTime": datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] })

@app.route('/about', methods=['GET'])
def about():
    return json.dumps({"resultCode": 0, "textKey": "key about helpers", "info": "some info"})

@app.route('/checkDevices', methods=['POST'])
def checkDevices():
    try:
        data = request.get_json()
        if data == {}:
            return json.dumps({"resultCode": 1, "errorMessage": "Empty request!"})
        target = data['target']
    except:
        return json.dumps({"resultCode": 1, "errorMessage": "Incorrect input data!"})
    try:
        result = scanByTable(target)
    except:
        return json.dumps({"resultCode": 1, "errorMessage": "scanByTable function returned error!"})
    return json.dumps(result)

@app.route('/deepScanning', methods=['POST'])
def deepScanning():
    try:
        data = request.get_json()
        if data == {}:
            return json.dumps({"resultCode": 1, "errorMessage": "Empty request!"})

        if (data['target']):
            target = data['target']
        else:
            return json.dumps({"resultCode": 1, "errorMessage": "Not detected device"})
        if (data['os'] == True):
            osFlag = True
        else:
            osFlag = False
        if (data['ports'] == True):
            portsFlag = True
        else:
            portsFlag = False
        if (data['tracert'] == True):
            tracertFlag = True
        else:
            tracertFlag = False
        if (data['type'] == True):
            typeScan = True
        else:
            typeScan = False

        uid = data['uid']
        if uid == "":
            return json.dumps({"resultCode": 1, "errorMessage": "Incorrect thread's uid! Error in deepScanning() in Network-scanner"})
    except:
        return json.dumps({"resultCode": 1, "errorMessage": "Incorrect input data!"})

    result = []
    try:
        event = Event()
        threading_pointer[uid] = event

        thread1 = Thread(target=deepScan, args=(json.dumps({"target": target}), osFlag, portsFlag, tracertFlag, typeScan, result, event, ))
        thread1.start()
        thread1.join()
    except:
        result = [{"resultCode": 1, "errorMessage": "deepScan function returned error!"}]
    return json.dumps(result[0])

@app.route('/scanNetwork', methods=['POST'])
def scanNetwork():
    try:
        data = request.get_json()
        if data == {}:
            return json.dumps({"resultCode": 1, "errorMessage": "Empty request!"})

        if (data['target']):
            target = data['target']
        else:
            return json.dumps({"resultCode": 1, "errorMessage": "Empty target!"})
    except:
        return json.dumps({"resultCode": 1, "errorMessage": "Incorrect input data!"})

    try:
        pattern = re.compile('^[\d]{1,3}[\.][\d]{1,3}[\.][\d]{1,3}[\.][\d]{1,3}\-[\d]{1,3}$')
        ip = pattern.findall(target)
        if ip != []:
            ip_list = prepareIP(ip[0])
            if ip_list == 1:
                return json.dumps({"resultCode": 1, "errorMessage": "Incorrect IP - range!"})
            else:
                return json.dumps(alternativeScan(ip_list))
    except:
        return json.dumps({"resultCode": 1, "errorMessage": "AlternativeScan function returned Error!"})

    try:
        result = networkScan(target)
    except:
        return json.dumps({"resultCode": 1, "errorMessage": "scanNetwork function returned Error!"})
    return json.dumps(result)

@app.route('/abortScanning', methods=['GET'])
def abortScanning():
    try:
        uid = request.args.get('uid')
        temp = threading_pointer.get(uid)
        del threading_pointer[uid]
        temp.set()
        return json.dumps({"resultCode": 0, "errorMessage": "success"})
    except:
        return json.dumps({"resultCode": 1, "errorMessage": "Exception when aborting device scan"})

app.run()