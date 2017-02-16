#!/usr/bin/env python
#-*- coding: utf-8 -*-

'''
log analyze server.
'''
import socket
import time
import os
import sys
import re
import signal
import logging
import daemon
import json
import urllib2
import threading
import sqlite3
from lockfile import pidlockfile
import global_constant as gc


running = True
db_conn = None
task_id = 0
socket_magic_end_str = '@whaley.cn_magic'

def get_analyze_mode():
    pass

def get_raw_log():
    pass


def time_format(strtime):
    if not re.match(r'\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}', strtime):
        logging.error('Unknow timestamp format: %s'%strtime)
        return 0
    tmp = strtime.split('.')
    local_time = time.strptime("%s-"%time.localtime().tm_year + tmp[0], "%Y-%m-%d %H:%M:%S")
    epochtime = time.mktime(local_time) + float(tmp[1])/1000
    return epochtime

def mode_fatal_capture(task):
    global running
    str_patten =''
    fatal_result = ''
    kwd_sre_pattern = gc.get_sre_pattern(task['module'])
    if task['add_kwd']:
        str_pattern = kwd_sre_pattern.pattern + '|' + task['add_kwd']
        kwd_sre_pattern = re.compile(str_pattern)
    elif not kwd_sre_pattern.pattern:
        logging.debug('No Key Word pattern for module: %d'%task['module'])
        return (False, 'Key word pattern absent!')
    logging.debug('str_patten: %s'%kwd_sre_pattern.pattern)
    start_time = time.time()
    try:
        for e_log_url in task['log_url']:
            ret = urllib2.urlopen(e_log_url)
            if ret.code != 200:
                raise Exception('get log fail: %s'%e_log_url)
            while running:
                line = ret.readline()
                if not line:
                    break
                if re.findall(kwd_sre_pattern,line):
                    fatal_result += line 
    except Exception,msg:
        logging.error('log_analyze fail: %s'%msg.message)
        return (False, msg.message)
    end_time = time.time()
    logging.debug("task time consume: %s second"%(end_time - start_time))
    if fatal_result:
        return (True, fatal_result)
    else:
        return (False, 'Match no keyword.')


def mode_1kwd_capture(task):
    global running
    kwd_sre_pattern = re.compile(task['add_kwd'])
    try:
        for e_log_url in task['log_url']:
            ret = urllib2.urlopen(e_log_url)
            if ret.code != 200:
                raise Exception('get log fail, url: %s'%e_log_url)
            while running:
                line = ret.readline()
                if line:
                    result = re.findall(kwd_sre_pattern, line)
                    if result:
                        return (True, line)
                else:
                    break
    except Exception,msg:
        logging.error('log_analyze fail: %s'%msg.message)
        return (False, msg.message)
    return (False, 'NA')


def send_warning(level,content):
    pass

def mode_1kwd_timestamp_capture(task):
    return (True, 'test result')

def mode_2kwd_gap_capture(task):
    event_list = gc.get_event_list(task['module'])
    if not event_list:
        return (False, 'No event key word pattern.')
    final_time_result = {}
    event_result = {}
    for event in event_list:
        event_result[str(event)]= ''
        final_time_result[str(event)]=[]
    start_time = time.time()
    try:
        for e_log_url in task['log_url']:
            ret = urllib2.urlopen(e_log_url)
            if ret.code != 200:
                raise Exception('get log fail: %s'%e_log_url)
            while running:
                line = ret.readline()
                if not line:
                    ret.close()
                    break
                for event in event_list:
                    if  re.findall(gc.event_sre_pattern_dict[str(event)], line):
                        event_result[str(event)] += line
                        print line
    except Exception,msg:
        logging.error('log_analyze fail: %s'%msg.message)
        return (False, msg.message)

    event_time_sync_pattern = r'(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+\d+\s+\d+\sD\s'\
                               + gc.get_time_sync_pattern() + r'(\d{13})'
    event_time_sync_sre_pat = re.compile(event_time_sync_pattern)
    for event in event_list:
        plt_kwd = gc.get_event_key_word(task['plt'],event)
        if len(plt_kwd) == 1:
            event_pattern = r'(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}).*?'+ plt_kwd[0]
            time_str_list = re.findall(event_pattern, event_result[str(event)])
            logging.info('event timestamp: %d'%event + ' -- {}'.format(time_str_list))
            logging.debug('event pattern: %s'%event_pattern)
            final_time_result[str(event)] = time_str_list
            continue

        if len(plt_kwd) == 2:
            print event_result[str(event)]
            event_pattern = r'(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+\d+\s+\d+\s[IEDWV]\s' + plt_kwd[0]\
                             + r'(.*?)(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+\d+\s+\d+\s[IEDWV]\s' + plt_kwd[1]
            time_str_list = re.findall(event_pattern, event_result[str(event)],re.S)
            logging.info('event timestamp: %d'%event + ' -- {}'.format(time_str_list))
            logging.debug('event pattern: %s'%event_pattern)
            if not time_str_list:
                continue
            for time_tuple in time_str_list:
                time_sync_gap = 0
                time_sync = re.findall(event_time_sync_sre_pat,time_tuple[1])
                if time_sync:
                    if len(time_sync)==1:
                        print time_sync
                        time_sync_gap = float(time_sync[0][1])/1000 - time_format(time_sync[0][0])
                    elif len(time_sync) > 1:
                        continue
                final_time_result[str(event)].append("%.3f"%(time_format(time_tuple[2])
                                                         - time_format(time_tuple[0])
                                                         - time_sync_gap))
        if len(plt_kwd) == 3:
            event_pattern = r'(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+\d+\s+\d+\s[IEDWV]\s' + plt_kwd[0]\
                             + r'(.*?)(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+\d+\s+\d+\s[IEDWV]\s' + plt_kwd[2]
            time_str_list = re.findall(event_pattern, event_result[str(event)],re.S)
            logging.info('event timestamp: %d'%event + ' -- {}'.format(time_str_list))
            logging.debug('event pattern: %s'%event_pattern)
            if not time_str_list:
                continue
            for time_tuple in time_str_list:
                time_begin_pattern = r'(.*\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+\d+\s+\d+\s[IEDWV]\s.*?' + plt_kwd[1] + r'.*'
                time_begin_str = re.findall(time_begin_pattern, time_tuple[1])
                if time_begin_str:
                    final_time_result[str(event)].append("%.3f"%(time_format(time_tuple[2])
                                                             - time_format(time_begin_str[0])))
                else:
                    final_time_result[str(event)].append(0.0)



#            event_pattern_time_sync = r'(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+\d+\s+\d+\s[IEDW]\s'+ plt_kwd[0]\
#                                     + r'.*?(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+\d+\s+\d+\sD\s'\
#                                     + gc.get_time_sync_pattern() + r'(\d{13})'\
#                                     + r'.*?(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}).*?' + plt_kwd[1]
#            time_str_list = re.findall(event_pattern_time_sync, event_result[str(event)],re.S)
#            if time_str_list:
#                logging.debug('event timestamp(time sync): %d'%event + ' -- {}'.format(time_str_list))
#                for time_tuple in time_str_list:
#                    time_sync_gap = float(time_tuple[2])/1000 - time_format(time_tuple[1]) 
#                    time_gap = time_format(time_tuple[3]) - time_format(time_tuple[0]) - time_sync_gap
#                    final_time_result[str(event)].append("%.3f"%time_gap)
#                break
#            else:

    end_time = time.time()
    logging.debug("task time consume: %f second"%(end_time - start_time))
    return (True, json.dumps(final_time_result))


def single_analyze(task):
    mode = int(task['mode'])
    if mode == gc.MODE_FATAL_KWDS_CAP:
        return mode_fatal_capture(task)
    elif mode == gc.MODE_1KWD_CAP:
        return mode_1kwd_capture(task)
    elif mode == gc.MODE_1KWD_TIMESTAMP_CAP:
        return mode_1kwd_timestamp_capture(task)
    elif mode == gc.MODE_2KWD_GAP_CAP:
        return mode_2kwd_gap_capture(task)
    else:
        logging.error('Unknow analyze mode: %d'%mode)
        return (False, 'Unknow analyze mode: %d'%mode)

def cluster_mode_2kwd_gap_capture(task):
    '''
    output format:
    (True,[(case_index,result)...])
    '''
    global running
    result = []
    if task['event'][1]:
         sre_patten = re.compile(task['event'][1][0] +'|'+ task['event'][1][1])

    cluster = task['cluster']
    for i in range(len(cluster)):
        for e_url in cluster[i][1]:
            try:
                ret = urllib2.urlopen(e_url)
                if ret.code != 200:
                    raise Exception('get log fail, url: %s'%e_url)
                while running:
                    line = ret.readline()
                    if line:
                        if re.findall(sre_patten,line):
                            if re.findall(task['event'][1][0],line):
                                first_time = get_timestamp(line)
                            else:
                                second_time = get_timestamp(line)

                            if first_time and second_time:
                                gap = second_time - first_time
                                result.append((cluster[i][0], gap))
                                first_time = second_time = 0
                    else:
                        ret.close()
                        break
            except Exception,msg:
                result.append((cluster[i][0], msg.message))
                logging.error('log_analyze fail: %s'%msg.message)
                return (False,result)
    return (True,result)
        
    
def cluster_analyze(task):
    mode = int(task['mode'])
    if mode == gc.MODE_2KWD_GAP_CAP:
        return cluster_mode_2kwd_gap_capture(task)

def realtime_analyze():
    pass

def specific_analyze():
    pass


def start_analyze(task):
    if task['type'] == gc.ANALYZE_TYPE_SINGLE:
        return single_analyze(task)
    elif task['type'] == gc.ANALYZE_TYPE_CLUSTER:
        return cluster_analyze(task)
    elif task['type'] == gc.ANALYZE_TYPE_RTIME:
        return realtime_analyze(task)
    elif task['type'] == gc.ANALYZE_TYPE_SPECIAL:
        return specific_analyze(task)
    else:
        logging.error('Unknow task_type: %d'%task_type)
        return (False, 'Unknow task_type: %d'%task_type)
    return (True,'OK')
 

def start_manage_service():
    return True

def db_write_record(task, ack, content):
    global db_conn
    c = db_conn.cursor()
    if task['type'] == gc.ANALYZE_TYPE_SINGLE:
        try:
            c.execute("INSERT INTO table_type_single VALUES \
                       (NULL,'%d','%d','%d','%s','%s')"\
                       %(task['module'],
                       task['mode'],
                       ack,
                       time.strftime('%Y-%m-%d %H:%M:%S',time.localtime()),
                       content))
        except Exception,msg:
#            logging.debug(content)
            logging.error('insert db fail. %s'%msg.message)
            return False
    if task['type'] == gc.ANALYZE_TYPE_CLUSTER:
        pass
    db_conn.commit()
    return True


def db_read_record():
    pass

def db_disconnect():
    global db_conn
    db_conn.close()

def db_init():
    global db_conn
    db_conn = sqlite3.connect('log_record.db', check_same_thread = False)
    c = db_conn.cursor()
    try:
        c.execute('SELECT tbl_name FROM sqlite_master WHERE type="table"')
        table_list = c.fetchall()
        if ('table_type_single',) not in table_list:
            c.execute('''CREATE TABLE table_type_single (Id integer primary key,
                                                         Module integer,
                                                         Mode integer,
                                                         Result integer,
                                                         Time text,  
                                                         Context text)''')
        if ('table_type_cluster',) not in table_list:
            c.execute('''CREATE TABLE table_type_cluster (Id integer primary key,
                                                          Mode integer,
                                                          Result integer,
                                                          Time text,
                                                          Context text)''')
    except Exception,msg:
        logging.error('init db fail.%s'%msg.message)
        return False
    return True


def url_valid(url):
    try:
        ret = urllib2.urlopen(url)
        if ret.code != 200:
            logging.error('log url not found: %s'%e_url)
            return gc.ERROR_URL_NOT_FOUND
        ret.close()
    except urllib2.HTTPError,msg:
        logging.error(msg)
        return gc.ERROR_URL_NOT_FOUND
    return gc.ERROR_URL_SUCCESS

def task_para_verify(task):
    try:
        if task['mode'] not in gc.get_analyze_mode_list():
            raise Exception('Un support log analyze mode: %d'%task['mode'])
        '''
        json format:
        {type:[int],
         plt:int
         module:[int],
         mode:[int],
         log_url:[string list]
         event:<{str: tuple}>
         add_kwd:<string list>,
         }

        '''
        if task['plt'] not in [1,2]:
            raise Exception('Unknow platform: %d'%task['plt'])
        if task['type'] == gc.ANALYZE_TYPE_SINGLE:
            if task['module'] not in gc.get_module_list():
                raise Exception('Unkown module: %s'%task['module'])
            for e_url in task['log_url']:
                if url_valid(e_url) != gc.ERROR_URL_SUCCESS:
                    raise Exception('url not found: %s'%e_url)
            if type(task['add_kwd']) != str:
                raise Exception('Need string type for add_kwd! Error type: %s'%type(task['add_kwd']))
        elif task['type'] == gc.ANALYZE_TYPE_CLUSTER:
            for e_case in task['cluster']:
                for e_url in e_case[1]:
                    if url_valid(e_url) != gc.ERROR_URL_SUCCESS:
                        raise Exception('url not found: %s'%e_log_url)
            #str_tuple is empty or not filled correctly.
            if task['event'][0] not in gc.get_event_list() and len(task['event'][1]) != 2:
                logging.error('Support events: {}'.format(gc.get_event_list()))
                raise Exception('Unknow analyze event: %s'%task['event'][0])
        elif task['type'] == gc.ANALYZE_TYPE_RTIME:
            pass
        elif task['type'] == gc.ANALYZE_TYPE_SPECIAL:
            pass
        else:
            raise Exception('Unknow task type: %s'%task['type'])
    except Exception, msg:
        logging.error(msg)
        return (False, msg.message)
    return (True,'OK')





def log_analyze_subthread(con, task):
    global task_id
    index = task_id = task_id + 1
    logging.info('New task, index: %d'%index)
    for item in task.items():
        logging.info('    '+ item[0]+': '+ '{}'.format(item[1]))
    response = {'ack': True, 'content': ''}
    ack,content = task_para_verify(task)
    if ack:
        ack,content = start_analyze(task)
#        if not db_write_record(task, ack, content):
#            logging.error('write db fail, task: {}'.format(task))
#            send_warning(1,'test critical')
    response['ack'] = ack
    response['content'] = unicode(content,errors='replace')
#    logging.info('task result, index: %d\n    ack: %s\n    %s'%(index, ack,response['content']))
    send_string = json.dumps(response)
    i = 0
    while len(send_string[i:])>1024:
        con.send(send_string[i:i+1024])
        i += 1024
    con.send(send_string[i:] + socket_magic_end_str)
    con.close()
    
def json_loads_byteified(json_text):
    return _byteify(
            json.loads(json_text, object_hook=_byteify),
            ignore_dicts=True)

def _byteify(data, ignore_dicts = False):
    # if this is a unicode string, return its string representation
    if isinstance(data, unicode):
        return data.encode('utf-8')
        # if this is a list of values, return list of byteified values
    if isinstance(data, list):
        return [ _byteify(item, ignore_dicts=True) for item in data ]
    # if this is a dictionary, return dictionary of byteified keys and values
    # but only if we haven't already byteified it
    if isinstance(data, dict) and not ignore_dicts:
        return {
                _byteify(key, ignore_dicts=True): _byteify(value, ignore_dicts=True)
                for key, value in data.iteritems()}
    # if it's anything else, return it in its original form
    return data

def start_listen_service():
    global socket_magic_end_str
    global running
    try:
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM) 
        s.bind(('0.0.0.0', gc.SOCKET_SERVER_PORT))
        s.listen(5)
        s.settimeout(1)
    except Exception,msg:
        print msg
        logging.error(msg)
        running = False
        sys.exit(1)
    logging.info('start socket seriver success.')
    while running :
        try:
            con,addr = s.accept()
        except socket.timeout:
            continue
        logging.info('new connection from: {}'.format(addr))
        con.settimeout(5)
        task_data =''
        while running:
            try:
                data = con.recv(1024) 
            except socket.timeout:
                logging.error('can not recieve data from {}'.format(addr))
                break
            task_data += data
            if task_data.endswith(socket_magic_end_str) or not data:
                break
        try:
            json_data = task_data[0:0-len(socket_magic_end_str)] 
            task = json_loads_byteified(json_data)
        except ValueError,msg:
            logging.error('fail to load json, raw string: "%s"'%task_data)
            logging.error(msg)
            con.close()
            continue
        task_thread = threading.Thread(target=log_analyze_subthread, args=(con, task), name='log_analyze_thread')
        task_thread.daemon = True
        task_thread.start()
    s.close()
    logging.debug('socket server thread exit successfully.')
    return

def env_check():
    return True

def log_config(loglevel=logging.DEBUG,fork=True):
    user_format = '%(asctime)s %(levelname)s %(funcName)s# %(msg)s'
    if not fork:
        logging.basicConfig(level=logging.DEBUG, stream=sys.stdout,format=user_format)
    logger = logging.getLogger()
    logger.setLevel(loglevel)
    handler = logging.FileHandler('/var/log_analyze.log')
    handler.setFormatter(logging.Formatter(user_format))
    logger.addHandler(handler)
    return logger
    
def signal_handler(signum, frame):
    global running
    logging.debug('signal handle: %d'%signum)
    if signum == signal.SIGINT or signum == signal.SIGTERM:
        running = False
    return
    

def main():
    global running
    loglevel = logging.DEBUG
    fork = False

    logger = log_config(loglevel,fork)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if fork:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)


    pidfile = '/var/run/log_analyze.pid'
    lockfile = pidlockfile.PIDLockFile(pidfile)
    if lockfile.is_locked():
        logging.error('PIDFile: %s already locked, log_analyze is running.'%pidfile)
        sys.exit(1)
    lockfile.acquire()

    if not env_check():
        logging.error('env check fail!')
        return False
    if not db_init():
        logging.error('init database fail!')
        return False

    listen_thd = threading.Thread(target=start_listen_service, name='socket_server_thread')
    listen_thd.daemon = True
    listen_thd.start()

    if not start_manage_service():
        logging.error('start manager serice fail.')
        sys.exit(1)
    logging.info('start manager service success.')

    while running:
        time.sleep(5)
    
    db_disconnect()
    lockfile.release()
    time.sleep(1)
    logging.info('log analyze process stop.')

if __name__ == '__main__':
    main()
#    print gc.get_event_key_word(4)
#    print gc.event_sre_pattern_dict[str(4)].pattern
#    print gc.get_event_key_word(4)[0]
#    print gc.get_event_key_word(1,3)
