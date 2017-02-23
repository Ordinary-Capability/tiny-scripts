#!/usr/bin/env python
#-*- coding: utf-8 -*-
import socket
import json
import time
import threading



SOCKET_SERVER_PORT = 50819
LOG_SERVER = '172.16.117.5'

ANALYZE_TYPE_SINGLE = 51
ANALYZE_TYPE_CLUSTER = 52
ANALYZE_TYPE_RTIME = 53
ANALYZE_TYPE_SPECIAL = 54

PLT_APOLLO = 1
PLT_HELIOS = 2

MDL_COMMON = 1
MDL_OTA = 2
MDL_SYSTEM = 3
MDL_WIFI = 4
MDL_SIGNAL = 5
MDL_MULTIMEDIA = 6
MDL_END = 7

#base fatal analyze mode
MODE_FATAL_KWDS_CAP = 1
#capture one key word in log, and return directly
MODE_1KWD_CAP = 2
MODE_1KWD_AVG_CALC = 3
MODE_1KWD_TIMESTAMP_CAP = 4
MODE_2KWD_GAP_CAP = 5  #need timestamp
MODE_2KWD_GAP_AVG_CALC = 6
MODE_RTIME_1KWD_CAP = 7#return timestamp
MODE_RTIME_2KWD_GAP_CAP = 8#return timestamp
MODE_END = 9

EVENT_LAUNCH_TIME = 1
EVENT_PRELOAD_TIME = 2
EVENT_WIFI_RETRIVE_STR = 3
EVENT_ZYGOTE_TIME = 4
EVENT_SYS_SERVER_TIME = 5
EVENT_PMS_TIME = 6
EVENT_PMS2AMS_TIME = 7
EVENT_AMS2LUT_TIME = 8
EVENT_WIFI_RETRIVE_AC_ONOFF = 9
EVENT_END = 10

def log_analyze(plt,module,log_list,mode=MODE_FATAL_KWDS_CAP):
    '''
    Method input para:
        plt: platform index:
            PLT_APOLLO = 1
            PLT_HELIOS = 2
        module: the module index:
            MDL_OTA = 2
            MDL_SYSTEM = 3
            MDL_WIFI = 4
            MDL_SIGNAL = 5
            MDL_MULTIMEDIA = 6

        mode: the context analyze mode index:
            #faltal keywords capture
            MODE_FATAL_KWDS_CAP = 1

            #capture and caculate the time between two lines with keywords in it.
            #and the ntp system time sync is considered, the time duration can be caculate correctly,
            #even if there's ntp system sync process between the start line and the end line.
            MODE_2KWD_GAP_CAP = 5
    '''
    request = {'type': 51,
               'plt':plt,
               'module': module,
               'mode': mode,
               'log_url': log_list,
               'add_kwd':''}
    socket_magic_end_str = '@whaley.cn_magic'
    try:
        s = socket.socket()
        s.settimeout(30)
        s.connect((LOG_SERVER, SOCKET_SERVER_PORT))
        send_data = json.dumps(request) + socket_magic_end_str
        s.send(send_data)

        data_recv = ''
        while True:
            data = s.recv(1024)
            if not data:
                break
            data_recv += data
            if data.endswith(socket_magic_end_str):
                break
    except Exception,msg:
        return (False, msg)

    response = json.loads(data_recv[0:0-len(socket_magic_end_str)])
    result = response['ack']
    if not result:
        return (False, response['content'])

    if mode in [MODE_FATAL_KWDS_CAP]:
        content = response['content'][0:1024]
    elif mode in [MODE_2KWD_GAP_CAP]:
        content = json.loads(response['content'])

    return (result,content)


if __name__ == '__main__':
    result, content = log_analyze(1,4,["http://172.16.117.1:8000/resource/zhengke/test_wifi_stress_5.log"],MODE_2KWD_GAP_CAP)
    print content
#    result, content = log_analyze(2,4,["http://172.16.117.1:8000/resource/zhengke/test_wifi_basic_4_1.log"],MODE_2KWD_GAP_CAP)
#    print content
#    result, content = log_analyze(1,3,["http://172.16.117.1:8000/resource/zhengke/test_factory_reset_keep_app-1_1_logcat.log"],MODE_2KWD_GAP_CAP)
#    print content
