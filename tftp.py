#! /usr/bin/env python
# -*- coding:utf-8 -*-



import time
import re
import pexpect
from utils import SocatCon
import curl

mboot_flag_patten= {'HELIOS':['set bootargs','<< MStar >>#',r'init:.*boot is finished'],
                    'APOLLO':['get extern rsa key success','apollo#',r'init:.*boot is finished']}
platform = '' 

def is_con_available(con):
    con.expect(['.+',pexpect.EOF,pexpect.TIMEOUT],timeout=5)
    con.sendline('echo')
    ret = con.expect([' [\$|#] ',pexpect.EOF,pexpect.TIMEOUT],timeout=1)
    if ret:
        print 'expect ret = ' + str(ret)
        print con.before
        return False
    else:
        return True


def input_para_parser(dut_ip,dut_port,image):
    """
   \\172.16.11.28\images\apollo-apollo_kktvd-release-01.24\APOLLO_KKTVD-01.24.00-1651304-24
    """
    global platform
    patten = re.compile(r'//[^/].*/images/\w+-.*/.*[^/]/?')
    if not re.match(patten,image):
        print "input image error: " + image
        return False
    
    patten = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    if not re.match(patten,dut_ip):
        print "input ip error: " + dut_ip

    patten = re.compile(r'\d+')
    if not re.match(patten,str(dut_port)):
        print "input port error: " + str(dut_port)
    
    platform = ''
    platform = re.findall(r'images/(\w+)-',image)[0].upper()
    print "test execute on platform========== " + platform
    if platform not in mboot_flag_patten.keys():
        print "unknow platform: " + platform
        return False

    return True

def get_su(con):
    con.sendline('su')
    if con.expect(['^su',pexpect.EOF,pexpect.TIMEOUT],timeout=0.2):
        return False
    return True


def env_check(con,image):
    patten = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    ser_ip = re.findall(patten,image)[0]  
    con.sendline('busybox ping '+ ser_ip + ' -c 3')
    if con.expect([r'bytes from .*seq.*ttl.*time.*ms',pexpect.EOF,pexpect.TIMEOUT],timeout=10):
        print "dut can not reach the server" + con.before
        return False

    return True

def enter_mboot(con):
    global platform
    con.sendline('reboot')
    while True:
        ret =  con.readline()
        if ret and re.findall(mboot_flag_patten[platform][0],ret):
            for i in range(10):
                con.sendline('\r')
                time.sleep(0.2)
            break
        print ret.replace('\r\n','')
    if con.expect([mboot_flag_patten[platform][1],pexpect.EOF,pexpect.TIMEOUT],timeout=0.2):
        print "fail to enter mboot:" + con.before
        return False

    return True

def image_flash(con,image):
    url = image.replace('//','') + '/success_mail.txt'
    cl = curl.Curl()
    buf = cl.get(url)
    set_cmd = re.findall('setenv serverip.*\n',buf)[0]
    flash_cmd = re.findall('mstar .*\n',buf)[0]
    con.sendline(set_cmd)
    con.sendline(flash_cmd)
    cl.close()
    return True

def result_verify(con,image):

    patten = re.compile(mboot_flag_patten[platform][2])
    while True:
        ret = con.readline()
        if ret and re.findall(patten,ret):
            return True
        print ret.replace('\r\n','')

    return False

def release_resource(con):
    con.close()
    return True

def set_connection(dut_ip,dut_port):
    socat_prefix = 'socat stdin,raw,echo=0 tcp:'
    command = socat_prefix + dut_ip +':'+ str(dut_port)
    con = pexpect.spawn(command,timeout = 150)
    if not is_con_available(con):
        print "setup connenction to dut fail!"
        return None
    if not get_su(con):
        print "fail to get su!"
        return None
    return con


def tftp_flash(dut_ip,dut_port,image):
    if not input_para_parser(dut_ip,dut_port,image):
        return False

    con = set_connection(dut_ip,dut_port)
    if not con:
        return False

    if not env_check(con,image):
        return False

    if not enter_mboot(con):
        return False

    if not image_flash(con,image):
        return False

    if not result_verify(con,image):
        return False

    if not release_resource(con):
        return False


    
if __name__ == '__main__':
    image = r'//172.16.11.28/images/helios-development/HELIOSD-01.25.00-1651301-326'
    dut_ip = '172.16.102.2'
    dut_port = 4196
#    image_flash('',image)
    tftp_flash(dut_ip,dut_port,image)

