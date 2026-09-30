#!/usr/bin/python3
# -*- coding: UTF-8 -*-

from starlette.applications import Starlette
from starlette.staticfiles import StaticFiles
from starlette.responses import HTMLResponse, PlainTextResponse, RedirectResponse, JSONResponse, Response
from starlette.templating import Jinja2Templates
from starlette.endpoints import WebSocketEndpoint, HTTPEndpoint
from starlette.routing import Route, WebSocketRoute, Mount
from starlette.websockets import WebSocket
# [YuHeng]: login and authentication
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.authentication import requires, AuthCredentials, AuthenticationBackend, SimpleUser
from starlette_auth_toolkit.cryptography import PBKDF2Hasher
from starlette_auth_toolkit.base.backends import BaseBasicAuth
from configparser import ConfigParser
from typing import NamedTuple
import base64
import re
from collections import OrderedDict
# [YuHeng]: database
import databases
import sqlalchemy

import magic
from CmdServer import *
import sys
sys.path.insert(1, './dynamic_result')
import uvicorn
import random
from typing import Any, Dict, List, Optional
from androguard.misc import AnalyzeAPK
from androguard.core.bytecodes.apk import APK
import threading
from threading import Timer
import json
from Global_setting import SETTING
from MobSFAPI import MobSF
import hashlib
import requests
from jinja2 import Environment, FileSystemLoader
import os
import time
from dynamic_result.DynamicWriter import GetAllResult

from web_static_analysis.activity_call_graph import androguard_acg_creator

from maldroid import androguard_server

import socket
import subprocess

TempResponse = Jinja2Templates(directory='/AndroidDynamicSystem/Frida/web_templates').TemplateResponse

app = Starlette(debug=True)
UPLOAD_APK_DIR = "/AndroidDynamicSystem/Frida/web_upload/"
APK_DECOMPILE_DIR = "/AndroidDynamicSystem/Frida/decompiled_apk/"
STATIC_ANALYSIS_DIR = "/AndroidDynamicSystem/Frida/static_analysis_result/"
WEB_STATIC = "/AndroidDynamicSystem/Frida/web_static/"
result_context = {}
applist = {}
APP_HASH = ''
hasher = PBKDF2Hasher()

def secure_filename(filename: str) -> str:
    """Sanitize filename to prevent directory traversal and special character injection."""
    filename = os.path.basename(filename or "")
    filename = re.sub(r"[^a-zA-Z0-9_.-]", "_", filename)
    filename = filename.lstrip(".")
    if not filename:
        filename = f"upload_{int(time.time())}.apk"
    return filename

# MOBSF_URL = "http://192.168.50.180:8000"
MOBSF_URL = "http://" + os.getenv('MOBSF', '172.27.0.3:8000')
host_ip = socket.gethostbyname(socket.gethostname())

class Static_recode:
    def __init__(self, stateName):
        self.stateName = stateName # example: com/example/mynewdiva/ButtonTestActivity
        self.analysisToolName = "" # "Androbug" "MobSF"
        self.problem = ""
        self.standard = ""
        self.level = ""
        self.md5 = ""
        self.others = ""
    def getHash(self):
        if self.md5 == "":
            m = hashlib.md5()
            m.update((self.analysisToolName + self.problem + self.level).encode())
            self.md5 = m.hexdigest()
        return self.md5

class APKinfo:
    def __init__(self, a, name, packName, d=None, dx=None):
        self.a, self.d, self.dx = a, d, dx
        self.filename = name
        self.staticAnalysisThread = None
        self.packageName = packName
        self.static_reslut = {} #dict: key = stateName : value = dict{key: md5 hash, value:  Static_recode}
        self.mobsfAPI = MobSF(MOBSF_URL)
        self.AndroBugsRes = None
        # get static result
        self.Static_analysis()
        self.VisitedState = None
        # [YuHeng]: for targeted orientation auto
        self.acg_creator = None
        self.newInstrApkPath = None
    def Hash_caculate(self):
        with open(f'{SETTING.UPLOAD_APK_DIR}/{self.filename}', "rb") as f:
            buf = f.read()
        m = hashlib.md5(buf)
        global APP_HASH
        APP_HASH = m.hexdigest()
        
    def Androguard_analysis(self):
        a, d, dx = AnalyzeAPK(f'{SETTING.UPLOAD_APK_DIR}/{self.filename}')
        self.a, self.d, self.dx = a, d, dx
        act = a.get_activities()
        actFile = open('/AndroidDynamicSystem/Frida/androguard/activites.txt','w')
        for i in range(len(act)):
            actFile.write(act[i] + '\n')
        actFile.close()
    def Androbug_analysis(self):
        # [halloworld]: python2 call maldroid
        safe_name = secure_filename(self.filename)
        server_thread = threading.Thread(target=androguard_server.run_androguard_server, args=(8010, os.path.join(SETTING.UPLOAD_APK_DIR, safe_name)))
        server_thread.start()
        subprocess.run([
            'python2',
            '/AndroidDynamicSystem/Frida/maldroid/maldroid_main.py',
            '-s', '-v',
            '-f', os.path.join(SETTING.UPLOAD_APK_DIR, safe_name),
            '-n', 'file',
            '-u', 'root'
        ], shell=False, check=False)
        jsonfile = self.packageName + ".json"
        path = STATIC_ANALYSIS_DIR + jsonfile
        if os.path.isfile(path):
            with open(path, "r") as f:
                data = json.load(f)
        else:
            print("[AndroBug]: json File doesn't ready")
            return None
        if "details" in data:
            detials = data["details"]
            self.AndroBugsRes = data
            for key in detials:
                if "vector_details" in detials[key]:
                    vecDetial = detials[key]["vector_details"]
                    for state in self.static_reslut.keys():
                        smaliName = state[1:-1]
                        javaName = state[1:-1].replace('/', '.')
                        if (smaliName in vecDetial) or (javaName in vecDetial):
                            # parse androbug data 
                            #print("Androbug Record!!!!!!!!!!!!!!!!!!!")
                            record = Static_recode(state)
                            if "title" in detials[key]: # problem title
                                record.problem = detials[key]["title"]
                            if "summary" in detials[key]: # CVE
                                record.standard = detials[key]["summary"]
                            if "level" in detials[key]: # notice level
                                record.level = detials[key]["level"]
                            record.others = vecDetial
                            record.analysisToolName = "Androbug"
                            self.Add_record_to_static_reslut(record)
    def MobSF_analysis(self):
        self.mobsfAPI = MobSF(MOBSF_URL)
        self.mobsfAPI.upload(f'{SETTING.UPLOAD_APK_DIR}/{self.filename}')
        self.mobsfAPI.scan()
        data = self.mobsfAPI.static_result
        if 'code_analysis' in data:
            for key in data['code_analysis'].keys():
                _tmp = data['code_analysis'][key]
                if "files" in _tmp and "metadata" in _tmp:
                    for filekey in _tmp["files"].keys():
                        record = Static_recode('L'+filekey[:-5]+';') # remove .java
                        record.analysisToolName = "MobSF"
                        if "description" in _tmp["metadata"]:
                            record.problem = _tmp["metadata"]["description"]
                        if "cvss" in _tmp["metadata"]:
                            record.standard += "cvss: " + str(_tmp["metadata"]["cvss"]) + ", "
                        if "cwe" in _tmp["metadata"]:
                            record.standard += "cwe: " + _tmp["metadata"]["cwe"] + ", "
                        if "owasp-mobile" in _tmp["metadata"]:
                            record.standard += "owasp-mobile: " + _tmp["metadata"]["owasp-mobile"] + ", "
                        if "masvs" in _tmp["metadata"]:
                            record.standard += "masvs: " + _tmp["metadata"]["masvs"] + ", "
                        if "severity" in _tmp["metadata"]:
                            record.level = _tmp["metadata"]["severity"]
                        record.others = "Line: " + _tmp["files"][filekey]
                        self.Add_record_to_static_reslut(record)
    def get_parent_head(self, startname):
        ReturnValue = []
        if self.dx != None:
            xref_from = list(self.dx.classes[startname].get_xref_from().keys())
            if len(xref_from) > 0:
                for _parent in xref_from:
                    if 'AppCompatActivity' in _parent.extends:
                        ReturnValue.append(_parent.name)
                        if _parent.name != startname:
                            ReturnValue.extend(self.get_parent_head(_parent.name))
        return ReturnValue

    def Get_issue_activity_list(self):
        issuaStateNameList = self.Get_issue_state()
        autoState = []
        if not self.staticAnalysisThread.is_alive():
            if(len(issuaStateNameList)>0):
                for _state in issuaStateNameList:
                    autoState.extend(self.get_parent_head(_state))
                    autoState.append(_state)
            autoState.append('L'+self.a.get_main_activity().replace('.','/')+';')
            autoState = list(dict.fromkeys(autoState))
        return autoState
        
                
    def Do_static_analysis(self):
        hashthread =  threading.Thread(target = self.Hash_caculate)
        mobsfthread = threading.Thread(target = self.MobSF_analysis)
        androbugthread = threading.Thread(target = self.Androbug_analysis)
        androguardthread = threading.Thread(target = self.Androguard_analysis)
        hashthread.start()
        mobsfthread.start()
        androbugthread.start()
        androguardthread.start()
        hashthread.join()
        mobsfthread.join()
        androbugthread.join()
        androguardthread.join()
    def Static_analysis(self):
        for _tmpAct in self.a.get_activities(): # set all activity
            self.static_reslut['L' + _tmpAct.replace('.','/') + ';'] = {}
        self.staticAnalysisThread = threading.Thread(target = self.Do_static_analysis)
        self.staticAnalysisThread.start()
    def get_source_code(self, statePath): # get from mobsf but the code is same as jadx you can change it to jadx
        realpath = statePath[1:-1] + ".java"
        print(realpath)
        if self.mobsfAPI.static_result != "": # after call scan finish the static_result will not be empty
            source = self.mobsfAPI.viewSource(realpath)
            #print("source: ", source)
            if "data" in source:
                return source["data"]
        return None

    def Add_record_to_static_reslut(self, record):
        md5key = record.getHash()
        stateName = record.stateName
        if stateName in self.static_reslut:
            if md5key not in self.static_reslut[stateName]:
                self.static_reslut[stateName][md5key] = record
        else:
            self.static_reslut[stateName] = {}
            self.static_reslut[stateName][md5key] = record
    
    def Get_current_state_static(self, stateName):
        ReturnList = []
        if stateName in self.static_reslut:
            for key in self.static_reslut[stateName].keys():
                _tmp = self.static_reslut[stateName][key]
                _appedDic = {}
                _appedDic["tools"] = _tmp.analysisToolName
                _appedDic["title"] = _tmp.problem
                _appedDic["standard"] = _tmp.standard
                _appedDic["level"] = _tmp.level
                _appedDic["others"] = _tmp.others
                ReturnList.append(_appedDic)
        return ReturnList

    def Get_static_result(self):
        if(not self.staticAnalysisThread.is_alive()):
            #print(self.static_reslut)
            return self.static_reslut.keys()
        else:
            return None
            #print("analysing..............")
    def Get_issue_state(self):
        ReturnList = []
        if not self.staticAnalysisThread.is_alive():
            for _key in self.static_reslut.keys():
                if(len(self.static_reslut[_key].keys()) > 0):
                    ReturnList.append(_key)
        return ReturnList
        #print("analysing..............")
    def Start_activity_call_graph_analyzie(self):
        if not self.staticAnalysisThread.is_alive():
            print("[+] ACG creator start working")
            self.acg_creator = androguard_acg_creator(self.a, self.d, self.dx)
            acg_creator_status = self.acg_creator.start()
            if(acg_creator_status):
                self.acg_creator.save_json(WEB_STATIC)
                return True
            else:
                print("[-] ACG creator have problem!")
                return False

# [halloworld]: LoopTimer for monitoring maldroid & MobSF
maldroid_state = 'none'
mobSF_for_monitoring_state_package_name = ''
class LoopTimer():
    '''
    t = perpetualTimer(1,maldroid_monitor)
    t.start()
    '''
    def __init__(self,t,hFunction):
        self.t=t
        self.hFunction = hFunction
        self.thread = Timer(self.t,self.handle_function)

    def handle_function(self):
        self.hFunction()
        self.thread = Timer(self.t,self.handle_function)
        # print("[handle_function]: {}".format(maldroid_state))
        if maldroid_state == 'success' or maldroid_state == 'fail':
            # print("[cancel]")
            self.thread.cancel()
        self.thread.start()

    def start(self):
        self.thread.start()

# [halloworld]: Monitoring maldroid & MobSF
def maldroid_monitor():
    # import os
    global maldroid_state
    maldroid_state_fd = os.open('/AndroidDynamicSystem/Frida/maldroid.state', os.O_RDWR)
    maldroid_state = os.read(maldroid_state_fd, 50).decode()
    os.close(maldroid_state_fd)
def getMaldroidStatus(): # 回傳 json
    global maldroid_state
    return {"maldroid_state": maldroid_state}
def getMobSFStatus(): # 回傳 json
    global mobSF_for_monitoring_state_package_name
    if mobSF_for_monitoring_state_package_name in applist.keys():
        return {"mobSF_state": applist[mobSF_for_monitoring_state_package_name].mobsfAPI.mobSF_state}
    return {"mobSF_state": "none"}

def decompile_apk(file_name):
    safe_name = secure_filename(file_name)
    base_decompile_name = safe_name[:-4] if safe_name.lower().endswith(".apk") else safe_name
    apk_target_path = os.path.join(SETTING.UPLOAD_APK_DIR, safe_name)
    out_decompile_dir = os.path.join(APK_DECOMPILE_DIR, base_decompile_name)
    subprocess.run(['jadx', '-d', out_decompile_dir, apk_target_path], shell=False, check=False)
    # python2
    subprocess.run([
        'python2',
        '/AndroidDynamicSystem/Frida/maldroid/maldroid_main.py',
        '-s', '-v',
        '-f', apk_target_path,
        '-n', 'file',
        '-u', 'root'
    ], shell=False, check=False)

def HomeResponse(request, context={}):
    template = "index.html"
    context = {"request": request }
    context.update(context)
    resp = TempResponse(template, context)
    return resp

class Homepage(HTTPEndpoint):
    async def get(self, request):
        return RedirectResponse(url="upload")
        # if(request.cookies.get('apk_name') != None) :
        #     if (request.cookies.get('apk_name') in applist):
        #         return HomeResponse(request)
        # elif (request.cookies.get('username') != None):
        #     return RedirectResponse(url="upload")
        # return RedirectResponse(url="login")
            
class Echo(WebSocketEndpoint):
    encoding = "text"
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cmdServer = None
        self.user_id = None
        self.m_socket = None
        self.package_name = None
        self.current_state = None
        # [YuHeng]:modify apkinof to apkinfo
        self.apkinfo = None 
        self.doing = False
        # [YuHeng]: init ACG creator status
        self.acg_status = False
    async def settingDisalbe(self, boo):
        self.doing = boo
        await self.m_socket.send_json({"status":"SETTING", "seting": boo})
    async def parse_action(self, action, data):
        if(action == "getMaldroidStatus"): # 取得 maldroid 的狀態
            maldroidStatus_json = getMaldroidStatus()
            await self.m_socket.send_json(maldroidStatus_json)
        if(action == "getMobSFStatus"): # 取得 mobsf 的狀態
            mobSFStatus_json = getMobSFStatus()
            await self.m_socket.send_json(mobSFStatus_json)
        if(action == "start"):
            if (self.package_name != None): #start control server
                await self.m_socket.send_json({"status":"INSTALLAPK"})
                apk_safe_name = secure_filename(self.apkinfo.filename)
                subprocess.run(['adb', '-s', str(SETTING.DEVICEID), 'install', '-t', os.path.join(UPLOAD_APK_DIR, apk_safe_name)], shell=False, check=False)
                await self.m_socket.send_json({"status":"SERVERSTARING"})
                self.cmdServer = ControlServer(SETTING.PORT)
                print(self.package_name)
                self.cmdServer.Start(websocket = self.m_socket, packname = self.package_name)
                print("ServerStart")
                await self.m_socket.send_json({"status":"ServerStart"})
            else:
                await self.m_socket.send_json({"status":"FAIL"})
        elif self.cmdServer != None:
            if(action == "auto"):
                res = self.cmdServer.RunCmdFromUser("auto", self.m_socket)
                if res >= 0:
                    await self.settingDisalbe(True)
                else:
                    await self.m_socket.send_json({"status":"SHOWMSG", "msgdata": "Dynamic Analysis Not Ready!!"})
            elif(action == "sauto"):
                if self.cmdServer != None:
                    if self.cmdServer.m_StaticAuto != None:
                        self.cmdServer.RunCmdFromUser("sauto", self.m_socket)
                        await self.settingDisalbe(True)
                    else:
                        await self.m_socket.send_json({"status":"SHOWMSG", "msgdata": "Static Analysis Not Ready!!"})
            elif(action == "tauto"):
                if self.cmdServer != None:
                    if self.cmdServer.m_TargetedAuto != None:
                        self.cmdServer.RunCmdFromUser("tauto", self.m_socket)
                        await self.settingDisalbe(True)
                    else:
                        await self.m_socket.send_json({"status":"SHOWMSG", "msgdata": "Target orientation Analysis Not Ready!!"})
            # [YuHeng]: test Activity scanner
            elif(action == "ascan"):
                if self.cmdServer != None:
                    if self.cmdServer.m_TargetedAuto != None:
                        self.cmdServer.RunCmdFromUser("ascan", self.m_socket)
                    else:
                        await self.m_socket.send_json({"status":"SHOWMSG", "msgdata": "Activity call graph Analysis Not Ready!!"})
            elif(action == "exit"):
                self.apkinfo.VisitedState = self.cmdServer.GetVisitedState()
                self.cmdServer.RunCmdFromUser("exit", self.m_socket)
                await self.settingDisalbe(False)
                print("Exit Success")
            elif(action == "getOutput"):
                if self.cmdServer != None:
                    mesg = self.cmdServer.get_webMesg()
                    tmpstate = self.cmdServer.GetState() # 這個是目前的 Activity 
                    if self.doing: # check if current mission finished
                        if self.cmdServer.m_iMode == 0: #MANUAL
                            await self.settingDisalbe(False)
                    if(self.cmdServer.m_StaticAuto == None):
                        if not self.apkinfo.staticAnalysisThread.is_alive():
                            # print("----------------------")
                            # print(self.apkinfo.Get_issue_state())
                            # print("----------------------")
                            # print(self.apkinfo.Get_issue_activity_list())
                            _res = self.cmdServer.Set_IssueState(self.apkinfo.Get_issue_state(), self.apkinfo.Get_issue_activity_list())
                            if _res >= 0:
                                await self.m_socket.send_json({"status":"CANSAUTO"})
                    if((self.cmdServer.m_TargetedAuto == None) and (self.cmdServer.m_ActivityScanner == None)):
                        if not self.apkinfo.staticAnalysisThread.is_alive():
                            # [YuHeng]: check acg is welldone?
                            self.acg_status = self.apkinfo.Start_activity_call_graph_analyzie()
                            if self.acg_status:
                                print("[+] ACG is down")
                                await self.m_socket.send_json({"status":"CANSHOWACG"})
                                await self.m_socket.send_json({"acg_monitor":self.cmdServer.m_CurrentDisplayActivity})
                                # await self.m_socket.send_json({"acg_monitor":self.cmdServer.m_RetrunCurrentActivity})
                                # [YuHeng]: start targeted auto and set can be visited activities to cmdSever
                                if(self.cmdServer.m_TargetedAuto == None):
                                    # _res = self.cmdServer.Set_TargetedAutoMode(self.apkinfo.acg_creator.get_can_visited_list(), self.apkinfo.acg_creator.get_implicit_intent_dict())
                                    _res = self.cmdServer.Set_TargetedAutoMode(self.apkinfo.acg_creator.get_all_activities(), self.apkinfo.acg_creator.get_implicit_intent_dict())
                                    if _res >= 0:
                                        print("Targeted auto is prepared!")
                                    else:
                                        print("Targeted auto is not prepared!")
                                if(self.cmdServer.m_ActivityScanner == None):
                                    _res = self.cmdServer.Set_ActivityScannerMode(self.apkinfo.acg_creator.get_all_activities(), self.apkinfo.acg_creator.get_implicit_intent_dict())
                                    if _res >= 0:
                                        print("Activity Scanner is prepared!")
                                    else:
                                        print("Activity Scanner is not prepared!")
                    if(self.acg_status and self.cmdServer.m_problemActivityFlag==True):
                        str_click_mode = 1 # [YuHeng]: click mode 1: 將 node 改變成紅色，紅色代表無法正常開啟的 activity
                        acg_Msg_list = str(str_click_mode) + "," + self.cmdServer.m_problemActivityName
                        await self.m_socket.send_json({"acg_monitor":acg_Msg_list})
                    elif(self.acg_status and self.cmdServer.m_problemActivityFlag==False):
                        if self.cmdServer.m_ActivityNameDiffFlag:
                            str_click_mode = 2 # [YuHeng]: click mode 2: 將 node 改變成綠色，綠色代表有正常跳轉但沒有停留在那個 activity
                            if self.cmdServer.m_jumpTargetActivityName != None:
                                acg_Msg_list = str(str_click_mode) + "," + self.cmdServer.m_jumpTargetActivityName
                                await self.m_socket.send_json({"acg_monitor":acg_Msg_list})
                            self.cmdServer.m_ActivityNameDiffFlag = False
                        elif self.cmdServer.m_ActivityNameDiffFlag!=True and self.cmdServer.m_CurrentDisplayActivity != None:
                            str_click_mode = 0 # [YuHeng]: click mode 0: 將 node 改變成黃色，黃色代表可以正常開啟的 activity
                            acg_Msg_list = str(str_click_mode) + "," + self.cmdServer.m_CurrentDisplayActivity
                            await self.m_socket.send_json({"acg_monitor":acg_Msg_list})
                    if(tmpstate != self.current_state):
                        self.current_state = tmpstate
                        if(self.current_state != None):
                            source_code = self.apkinfo.get_source_code(self.current_state)
                            loadtext = self.cmdServer.GetAvaliableText()
                            noticeProblem = self.apkinfo.Get_current_state_static(self.current_state)
                            if(source_code != None):
                                await self.m_socket.send_json({"java_source":source_code})
                            else:
                                await self.m_socket.send_json({"java_source":"No Source Code"})
                            await self.m_socket.send_json({"avalible_text":loadtext})
                            await self.m_socket.send_json({"problem":noticeProblem})
                    if(type(mesg) is str):
                        await self.m_socket.send_json({"log_mesg":mesg})
                    else:
                        await self.m_socket.send_json({"status":"STOPINTERVAL"})
            elif(action == "manual"):
                self.cmdServer.RunCmdFromUser("manual", self.m_socket)
            elif(action == "loadjson"):
                tostate_list = self.cmdServer.RunCmdFromUser("loadjson", self.m_socket)
                await self.m_socket.send_json({"status":"LOADSUCCESS", "tostate_list":tostate_list})
            elif(action == "goto"):
                if("toState" in data):
                    self.cmdServer.RunCmdFromUser(action = "goto", data = data, socket = self.m_socket)
                    await self.settingDisalbe(True)
            elif(action == "loadcurr"):
                tostate_list = self.cmdServer.RunCmdFromUser("loadcurr", self.m_socket)
                await self.m_socket.send_json({"status":"LOADSUCCESS", "tostate_list":tostate_list})
            elif(action == "save_record"):
                result = self.cmdServer.RunCmdFromUser(action = "save_record", socket = self.m_socket)
                if result:
                    await self.m_socket.send_json({"status":"SHOWMSG", "msgdata": "Save record Success!!"})
            elif(action == "showall"):
                self.cmdServer.RunCmdFromUser(action = "showall", socket = self.m_socket)
            elif(action == "fuzz"):
                if("FuzzID" in data):
                    self.cmdServer.RunCmdFromUser(action = "fuzz", data = data , socket = self.m_socket)
                    await self.settingDisalbe(True)
            elif(action == "setpa"):
                if("setacc" in data and "setpass" in data and "settext" in data):
                    result = self.cmdServer.RunCmdFromUser(action = "setpa", data = data , socket = self.m_socket)
                if result:
                    await self.m_socket.send_json({"status":"SHOWMSG", "msgdata": "Set Account and Password Success!!"})
                else:
                    await self.m_socket.send_json({"status":"SHOWMSG", "msgdata": "Set Account and Password Failed!"})
            elif(action == "jump"):
                if("jumpActName" in data):
                    result = self.cmdServer.RunCmdFromUser(action = "jump", data = data)
                if result:
                    await self.m_socket.send_json({"status":"SHOWMSG", "msgdata": "Jump to target Activity Success!!"})
                else:
                    await self.m_socket.send_json({"status":"SHOWMSG", "msgdata": "Jump to target Activity Failed!"})
        elif(action == "getMaldroidStatus" and self.cmdServer == None):
            # print("in the maldroid")
            await self.m_socket.send_json({"status":"STATIC"})
        # Send Finish status to website, then reset mobsf_state to none
        elif(action == "STATIC_FIN" and self.cmdServer == None):
            await self.m_socket.send_json({"status":"STATIC_FIN"})
            f = open('/AndroidDynamicSystem/Frida/maldroid.state','w')
            f.write("none")
            f.close()  
        else:
            print(action)
            # await self.m_socket.send_json({"status":"UnknownAction"})
    async def on_connect(self, websocket):
        await websocket.accept()
        self.user_id = str(random.random())
        # await websocket.send_json(
        #     {"id": self.user_id}
        # )
        print(self.user_id)
        print("Here is websocket", websocket)
        self.m_socket = websocket
    async def on_receive(self, _websocket: WebSocket, msg: Any):
        if self.user_id is None:
            raise RuntimeError("on_receive() called without a valid user_id")
        if not isinstance(msg, str):
            raise ValueError(f"on_receive() passed unhandleable data: {msg}")
        data = json.loads(msg)
        if('action' in data):
            await self.parse_action(data['action'], data)
        if('packname' in data):
            print(data['packname'])
            if data['packname'] != 'undefined':
                self.package_name = data['packname']
                self.apkinfo = applist[self.package_name]
    async def on_disconnect(self, _websocket: WebSocket, _close_code: int):
        if self.user_id is None:
            raise RuntimeError(
                "on_disconnect() called without a valid user_id"
            )
        if self.cmdServer != None:
            self.cmdServer.RunCmdFromUser("exit", _websocket)

class Result(HTTPEndpoint):
    '''
    Show Result
    '''
    async def get(self, request):
        if request.cookies.get('apk_name') != None :
            if request.cookies.get('apk_name') in applist:
                package_name = request.cookies.get('apk_name')
                _appinfo = applist[package_name]            
                # [halloworld]: pull the dynamic result
                subprocess.run(["adb", "-s", str(SETTING.DEVICEID), "root"], shell=False, check=False)
                safe_package_name = re.sub(r'[^a-zA-Z0-9_.-]', '', package_name)
                pull_dest = f"/AndroidDynamicSystem/Frida/static_analysis_result/{safe_package_name}.log.txt"
                subprocess.run(["adb", "-s", str(SETTING.DEVICEID), "pull", f"/data/data/{safe_package_name}/files/LogFile.txt", pull_dest], shell=False, check=False)
                with open(pull_dest, "r", encoding="utf-8", errors="replace") as f:
                    raw_data = f.readlines()

                # [halloworld]: VistedState/MobSF/AndroBugs Result
                _VisitedState = []
                AndroBugsResultLog = {}
                mobsfAPILog = {}
                if _appinfo.VisitedState != None:
                    _VisitedState = _appinfo.VisitedState
                if _appinfo.mobsfAPI != None:
                    try:
                        mobsfAPILog = _appinfo.mobsfAPI.static_result.copy()
                    except:
                        mobsfAPILog = {"code_analysis": {}}
                else:
                    mobsfAPILog = {"code_analysis": {}}
                if _appinfo.AndroBugsRes != None:
                    AndroBugsResultLog = _appinfo.AndroBugsRes.copy()
                else:
                    AndroBugsResultLog = {"details": {}}
                result = GetAllResult(package_name, 
                                    mobsfAPILog, 
                                    AndroBugsResultLog, 
                                    SETTING.STATIC_DYNAMIC_MAPPING, 
                                    raw_data, 
                                    _VisitedState)
                '''
                r = requests.post("http://pdf-generator:15148/api/report", json=result)
                headers = {"Content-type": "application/pdf"}
                # [yiting]: Starlette Response
                return Response(r.content, headers=headers)
                '''
                return JSONResponse(result)
        return HTMLResponse(content="404", status_code=404)
        
# [Static report] Dy system can also generate static report(after click "static result")
class Static_Result(HTTPEndpoint):
    async def get(self, request):
        output_pdf_url = "http://"+host_ip+":15148/api/report"
        with open('/AndroidDynamicSystem/Frida/test.json','r') as infile:
            test = json.load(infile,object_pairs_hook=OrderedDict)
        res = requests.post(output_pdf_url, json=test, timeout=5)
        headers = {"Content-type": "application/pdf"}
        return Response(res.content, headers=headers)
class History_Result(HTTPEndpoint):
    async def get(self, request):
        configParser = ConfigParser()
        configParser.read("/AndroidDynamicSystem/Frida/config/Dy-db.cfg")
        MongoDB_Hostname = configParser.get('DB_Config', 'MongoDB_Hostname')
        MongoDB_Port = configParser.getint('DB_Config', 'MongoDB_Port')
        MongoDB_Database = configParser.get('DB_Config', 'MongoDB_Database')
        Collection_Analyze_Result = configParser.get('DB_Collections',
                                            'Collection_Analyze_Result')
        from pymongo import MongoClient
        client = MongoClient(MongoDB_Hostname, MongoDB_Port)
        db = client[MongoDB_Database]
        collection_Analyze_Result = db[Collection_Analyze_Result]
        md5 = APP_HASH
        if(collection_Analyze_Result.find_one({"md5": md5})):
            json_result = collection_Analyze_Result.find_one({"md5": md5})
            json_result.pop('_id')
            output_pdf_url = " http://pdf-generator:15148/api/report"
            res = requests.post(output_pdf_url, json=json_result, timeout=5)
            headers = {"Content-type": "application/pdf"}
            return Response(res.content, headers=headers)
        else:
            return HTMLResponse(content="HTML_404_PAGE", status_code=404)
class Upload(HTTPEndpoint):
    # @requires("authenticated", redirect='homepage')
    async def get(self, request):
        f = open('/AndroidDynamicSystem/Frida/maldroid.state','w')
        f.write("none")
        f.close()    
        template = "upload.html"
        context = {"request": request, "status": 'Please upload apk file'}
        resp = TempResponse(template, context)
        # TODO something problem for cookie
        resp.set_cookie(key = "User", value = str(random.random()))
        return resp
    # @requires("authenticated", redirect='homepage')
    async def post(self, request):

        global mobSF_for_monitoring_state_package_name
        form = await request.form()
        # Gather all files from the same field name (supports multi-upload)
        try:
            files = form.getlist("upload_file")
        except Exception:
            files = [form["upload_file"]] if "upload_file" in form else []

        # Minimal debug: total count and filenames
        print(f"[Upload] total files: {len(files)}")
        print(f"[Upload] filenames: {[getattr(f, 'filename', None) for f in files]}")

        if not files:
            template = "upload.html"
            context = {"request": request, "status": 'No file uploaded'}
            return TempResponse(template, context)

        # Choose base APK: prefer non-split_config *.apk; fallback to any *.apk
        base_file = None
        for file in files:
            name = (getattr(file, 'filename', '') or '')
            lname = name.lower()
            if name.endswith('.apk') and not lname.startswith('split_config'):
                base_file = file
                break

        if base_file is None:
            template = "upload.html"
            context = {"request": request, "status": 'The file is Not an apk'}
            return TempResponse(template, context)

        # Read and validate base APK first (no disk write until validated)
        raw_base_name = base_file.filename or ""
        filename = secure_filename(raw_base_name)
        contents = await base_file.read()
        file_mime = magic.from_buffer(contents, mime=True)
        if filename.endswith('.apk') and ("application/zip" in file_mime or "application/java-archive" in file_mime):
            # Save all uploaded files; write base using bytes we already read
            for f in files:
                raw_fname = getattr(f, 'filename', None)
                if not raw_fname:
                    continue
                safe_fname = secure_filename(raw_fname)
                if not safe_fname.lower().endswith('.apk'):
                    continue
                if f is base_file:
                    data = contents
                    filename = safe_fname
                else:
                    data = await f.read()
                dest_file_path = os.path.join(UPLOAD_APK_DIR, safe_fname)
                if not os.path.abspath(dest_file_path).startswith(os.path.abspath(UPLOAD_APK_DIR)):
                    raise ValueError(f"Path traversal detected in upload filename: {raw_fname}")
                with open(dest_file_path, "wb") as out:
                    out.write(data)
            # Get package name
            a = APK(os.path.join(UPLOAD_APK_DIR, filename))
            package_name = a.get_package()
            # [halloworld]: monitor mobsf
            mobSF_for_monitoring_state_package_name = package_name
            applist[package_name] = APKinfo(a=a, name=filename, packName=package_name)

            # [halloworld]: monitor the maldroid
            t = LoopTimer(3, maldroid_monitor)
            t.start()
            resp = HomeResponse(request)
            resp.set_cookie(key="apk_name", value=package_name)
            return resp
        else:
            template = "upload.html"
            context = {"request": request, "status": 'The file is Not an apk'}
            resp = TempResponse(template, context)
            return resp

async def not_found(request, exc):
    return HTMLResponse(content="HTML_404_PAGE", status_code=404)

async def server_error(request, exc):
    return HTMLResponse(content="HTML_500_PAGE", status_code=505)


# [YuHeng]: set, clear and get function for session
async def setup_session(request, username):
    request.session.update({'User': username})
    return JSONResponse({"session": request.session})
async def clear_session(request):
    request.session.clear()
    return JSONResponse({"session": request.session})
def view_session(request):
    return JSONResponse({"session": request.session})


routes = [
    Route("/", Homepage, name="homepage"),
    WebSocketRoute("/ws", Echo),
    Mount('/static', app=StaticFiles(directory='/AndroidDynamicSystem/Frida/web_static'), name="static"),
    Route("/upload", Upload, name="upload"),
    Route("/result", Result, name="result"),
    Route("/static-result", Static_Result, name="static-result"),
    Route("/history-result", History_Result, name="static-result"),
    # [halloworld]: API for get status
    Route("/maldroidStatus", endpoint=getMaldroidStatus, methods=["GET"]),
    Route("/mobSFStatus", endpoint=getMobSFStatus, methods=["GET"]),
]


exception_handlers = {
    404: not_found,
    500: server_error
}

app = Starlette(
    routes=routes,
    exception_handlers=exception_handlers
)

if __name__ == "__main__":
    uvicorn.run(app, host='0.0.0.0', port=8080)