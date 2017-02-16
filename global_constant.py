#!/usr/bin/env python
#-*- coding:utf-8 -*-

'''
global constant variable, to controll the  uniformity of the string used

in code
'''
import re

SOCKET_SERVER_PORT = 50819
SOCKET_MANAGE_PORT = 50820

'''
json format:
{type: [int],
 mode: [int],
 cluster: [(case_index: [log_url])],
 event: (event_name_str, str_tuple)}
'''
ANALYZE_TYPE_SINGLE = 51
ANALYZE_TYPE_CLUSTER = 52
ANALYZE_TYPE_RTIME = 53
ANALYZE_TYPE_SPECIAL = 54

MDL_COMMON = 1
MDL_OTA = 2
MDL_SYSTEM = 3
MDL_WIFI = 4
MDL_SIGNAL = 5
MDL_MULTIMEDIA = 6
MDL_END = 7

def get_module_list():
    global MDL_END
    return range(1,MDL_END)

PLT_HELIOS = 'HELIOS'
PLT_APOLLO = 'APOLLO'
PLT_TITIAN = 'TITIAN'
PLT_SPHNIX = 'SPHNIX'
PLT_PHOEBUS = 'PHOEBUS'
PLT_CRONUS = 'CRONUS'

MSG_FAIL = 'FAIL'
MSG_PASS = 'PASS'
MSG_NA = 'NA'

ERROR_URL_SUCCESS = 0
ERROR_URL_NOT_FOUND = -1


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
def get_analyze_mode_list():
    global MODE_END
    return range(1,MODE_END)

_FATAL_KEY_WORD = {
    str(MDL_OTA): [r'Stop requested with status FILE_ERROR: Failed to generate filename',
                   r'FATAL EXPECTION',
                   r'beginning of crash',
                   r"Can't connect to tvmanager server.Please check tvapi server!",
                   r'E WhaleyOTA.UpdateInfo: version is invalid',
                   r'E WhaleyOTA.APIUtils:  ex:.*No address associated with hostname',
                   r'E WhaleyOTA.APIUtils:  ex:.*String cannot be converted to JSONObject',
                   r'E WhaleyOTA.FileManager: file md5 mismatch!',
                   r'D WhaleyOTA.ContentObserver: STATUS_FAILED',
                   r'D WhaleyOTA.ContentObserver: Downloading status: 16 offset:0 total:-1',
                   r'E WhaleyOTA.UpdateService:Service is null',
                   r'E WhaleyOTA.OTAProxy:Failed to get permission',
                   r'E WhaleyOTA.OTAProxy:Failed to get the update progress',
                   r'E WhaleyOTA.OTAProxy:The update service is null',
                   r"D WhaleyOTA.OTAService:Downloading can't get file size",
                   r'E WhaleyOTA.OTAService:Download Failed. Reason:',
                   r"E WhaleyOTA.OTAService:There's no new update",
                   r'E WhaleyOTA.OTAService:Failed to fetch rom info',
                   r'E WhaleyOTA.OTAService:Failed to manager.getLocalFileUrii\(\)',
                   r'E WhaleyOTA.OTAService:ex:',
                   r'E WhaleyOTA.OTAService:Failed to fetch version info',
                   r'E WhaleyOTA.OTAService:The update service is null',
                   r'E WhaleyOTA.OTAService:Failed to get the update progress',
                   r'E WhaleyOTA.PropUtils:Failed to call isUpdateCorrupt',
                   r'E WhaleyOTA.PropUtils:The update service is null',
                   r'E WhaleyOTA.PropUtils:version is invalid',
                   r'E WhaleyOTA.APIUtils:Failed to generate string entity',
                   r'E WhaleyOTA.FileManager:localPath is null or empty',
                   r'E WhaleyOTA.FileManager:file not exist!',
                   r'E WhaleyOTA.FileManager:file size mismatch!',
                   r'E WhaleyOTA.FileManager:file md5 mismatch!',
                   r"E WhaleyOTA.Reboot:Can't open InstallPackage",
                   r'E WhaleyOTA.Reboot:Failed to verify the package',
                   r'E WhaleyOTA.Reboot:Unknown value',
                   r'E WhaleyOTA.Reboot:Failed to upgrade: in progress',
                   r'E WhaleyOTA.Reboot:Failed to upgrade /',
                   r'E WhaleyOTA.Reboot:Failed to upgrade /system/bin/whaley_update_client  /',
                   r'E WhaleyOTA.Reboot:Failed to install /',
                   r"E WhaleyOTA.Reboot:Can't wipe user data",
                   r'E WhaleyOTA.UpdateInfo:ex:',
                   r'E WhaleyOTA.UpdateInfo:.*is invalid',
                   r'E WhaleyOTA.ReleaseNote:ex:',
                   r'E WhaleyOTA.Test:Failed to sleep 1 second',
                   r'E WhaleyOTA.VendorImpl:Failed to switch boot system',
                   ],

    str(MDL_SYSTEM): [],
    str(MDL_WIFI): [r'netlink response contains error',
                    r'NativeDaemonConnectorException',
                    r'NetUti.*fail',
                    r'dhcp.*fail',
                     ],
    str(MDL_SIGNAL): [r'get timming fail!',
                      r'I2C1 Init Failure!',
                      r'I2C0 Init Failure!',
                      r'param pstEdidHdcp error',
                      r'malloc pstEdidHdcp->pstEdidList memery failure',
                      r'pstEdidHdcp->pstEdidList\[1-3\]\.pu32Edid memery failure!',
                      r'kfifo alloc ERROR!!!',
                      r'EnQueue ERROR!!',
                      r'DeQueue ERROR!!',
                      r'malloc pstEdidHdcp->penHdcpType memery failure!',
                      r'malloc pstEdidHdcp->pstHdcpList memery failure!',
                      r'malloc pstEdidHdcp->pstHdcpList\[0-1\]\.pu8Hdcp memery failure!',
                      ],
    str(MDL_MULTIMEDIA): [r"play-   --onReceivePlayEvent event:109",
                          r"play-   --UrlParserCallback  success:false",
                          r"request-   request playInfo error",
                          r"\[MiddleWare-player onError\] \d+_\d+_\d",
                          r"onPlayInfoError.*\(errorCode",
                          r"MiddleWare-player\s*onError",
                          r"SocketTimeoutException",
                          r"SocketException",
                          r"Unable to connect to",
                          r"$InvalidResponseCodeException",
                          ],
    str(MDL_COMMON): [r"fail|Fail|FAIL|error|Error|ERROR|invalid|Invalid|INVALID",
                          ]
                }

def _build_sre_pattern(module):
    global _FATAL_KEY_WORD
    str_pattern = ''
    for e in _FATAL_KEY_WORD[str(module)]:
        str_pattern += ('|' + e)
    return re.compile(str_pattern[1:])

fatal_sre_pattern_ota = _build_sre_pattern(MDL_OTA) 
fatal_sre_pattern_system = _build_sre_pattern(MDL_SYSTEM)
fatal_sre_pattern_wifi = _build_sre_pattern(MDL_WIFI)
fatal_sre_pattern_signal = _build_sre_pattern(MDL_SIGNAL)
fatal_sre_pattern_multimedia = _build_sre_pattern(MDL_MULTIMEDIA)
fatal_sre_pattern_common = _build_sre_pattern(MDL_COMMON)

def get_sre_pattern(module):
    global fatal_sre_pattern_ota 
    global fatal_sre_pattern_system
    global fatal_sre_pattern_wifi
    global fatal_sre_pattern_signal
    global fatal_sre_pattern_multimedia
    if module == MDL_COMMON:
        return fatal_sre_pattern_common
    if module == MDL_OTA:
        return fatal_sre_pattern_ota
    if module == MDL_SYSTEM:
        return fatal_sre_pattern_system
    if module == MDL_WIFI:
        return fatal_sre_pattern_wifi
    if module == MDL_SIGNAL:
        return fatal_sre_pattern_signal
    if module == MDL_MULTIMEDIA:
        return fatal_sre_pattern_multimedia

def get_fatal_key_word(module):
    global _FATAL_KEY_WORD
    return _FATAL_KEY_WORD[str(module)]


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


_MODULE_EVNT_DIC = {
                    str(MDL_SYSTEM):[EVENT_LAUNCH_TIME,
                                     EVENT_PRELOAD_TIME,
                                     EVENT_ZYGOTE_TIME,
                                     EVENT_SYS_SERVER_TIME,
                                     EVENT_PMS_TIME,
                                     EVENT_PMS2AMS_TIME,
                                     EVENT_AMS2LUT_TIME],
                    str(MDL_WIFI):[EVENT_WIFI_RETRIVE_STR,
                                   EVENT_WIFI_RETRIVE_AC_ONOFF],
                    }

#01-01 20:00:14.311  1689  2028 D NetworkTimeUpdateService: Ntp time to be set = 1486722218490
_TIME_SYNC = "NetworkTimeUpdateService: Ntp time to be set = "
def get_time_sync_pattern():
    global _TIME_SYNC
    return _TIME_SYNC

_EVENT_KEY_WORD = {
    str(EVENT_LAUNCH_TIME):
                        [('ActivityManager: START u0', 'Kernel.*?init: Bootanimation is turned off')],
    str(EVENT_PRELOAD_TIME):
                        [('boot_progress_preload_start', 'boot_progress_preload_end')],
    str(EVENT_ZYGOTE_TIME):
                        [(r'START com\.android\.internal\.os\.ZygoteInit',)],
    str(EVENT_SYS_SERVER_TIME):
                        [('boot_progress_system_run', 'boot_progress_pms_start')],
    str(EVENT_PMS_TIME):
                        [('boot_progress_pms_start', 'boot_progress_pms_scan_end')],
    str(EVENT_PMS2AMS_TIME):
                        [('boot_progress_pms_ready', 'boot_progress_ams_ready')],
    str(EVENT_AMS2LUT_TIME):
                        [('boot_progress_ams_ready', 'ActivityManager: START u0')],
    str(EVENT_WIFI_RETRIVE_STR):
                        [(r'FeatureConnectivity: ResumeBegin', r'WifiStateMachine:\sWifiStateMachine DHCP successful'),
                         (r'ScreenPowerReceiver: action=android.intent.action.SCREEN_ON', r'WifiStateMachine:\sWifiStateMachine DHCP successful')],
    str(EVENT_WIFI_RETRIVE_AC_ONOFF):
                        [(r'WifiStateMachine:\ssetWifiState: enabled',\
                              r'ADT TEST LOG GET LAUNCHER',\
                              r'WifiStateMachine:\sWifiStateMachine DHCP successful'),
                          ()],
                  }

def _build_event_sre_pattern(event):
    global _EVENT_KEY_WORD
    global _TIME_SYNC
    raw_str = ''
    if not _EVENT_KEY_WORD[str(event)]:
        return None
    for m in _EVENT_KEY_WORD[str(event)]:
        for n in m:
            raw_str +=('|' + n)
    if not raw_str:
        return None
    sre_pattern = re.compile(_TIME_SYNC + raw_str)
    return sre_pattern

event_launch_time = _build_event_sre_pattern(str(EVENT_LAUNCH_TIME))
event_preload_time = _build_event_sre_pattern(str(EVENT_PRELOAD_TIME))
event_zygote_time = _build_event_sre_pattern(str(EVENT_ZYGOTE_TIME))
event_pms_time = _build_event_sre_pattern(str(EVENT_PMS_TIME))
event_pms2ams_time = _build_event_sre_pattern(str(EVENT_PMS2AMS_TIME))
event_ams2lut_time = _build_event_sre_pattern(str(EVENT_AMS2LUT_TIME))
event_wifi_retrive = _build_event_sre_pattern(str(EVENT_WIFI_RETRIVE_STR))
event_sys_server_time = _build_event_sre_pattern(str(EVENT_SYS_SERVER_TIME))
event_wifi_retrive_ac_onoff = _build_event_sre_pattern(str(EVENT_WIFI_RETRIVE_AC_ONOFF))


event_sre_pattern_dict = {str(EVENT_LAUNCH_TIME): event_launch_time,
                          str(EVENT_PRELOAD_TIME): event_preload_time,
                          str(EVENT_ZYGOTE_TIME): event_zygote_time,
                          str(EVENT_SYS_SERVER_TIME): event_sys_server_time,
                          str(EVENT_PMS_TIME): event_pms_time,
                          str(EVENT_PMS2AMS_TIME): event_pms2ams_time,
                          str(EVENT_AMS2LUT_TIME): event_ams2lut_time,
                          str(EVENT_WIFI_RETRIVE_STR): event_wifi_retrive,
                          str(EVENT_WIFI_RETRIVE_AC_ONOFF): event_wifi_retrive_ac_onoff}
                
def get_evnet_sre_pattern(event):
    return event_sre_pattern_dict[str(event)]

def get_event_list(module):
    global _MODULE_EVNT_DIC
    if str(module) in _MODULE_EVNT_DIC.keys():
        return _MODULE_EVNT_DIC[str(module)]
    else:
        return []

def get_event_key_word(plt,event):
    global _EVENT_KEY_WORD
    if plt == 1: #apollo 
        return _EVENT_KEY_WORD[str(event)][0]
    if plt == 2: #helios
        return _EVENT_KEY_WORD[str(event)][1]


if __name__ == '__main__':
    print _build_event_sre_pattern(4).pattern
