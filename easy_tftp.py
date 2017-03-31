#!/usr/bin/env python
#-*- coding:utf-8 -*-


import curl
import traceback
import parser
import pexpect
import logging
import time
import re
import sys


plt_list = ['HELIOS', 'APOLLO']

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
    con = pexpect.spawn(command,timeout = 250)
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


    

def retrieve_images(plt):
    global helios
    global apollo
    child = pexpect.spawn('smbclient //172.16.11.28/images -U guests%helios2015')
    child.sendline('l')
    ret = child.expect(['\d+ blocks of size \d+\. \d+ blocks available', pexpect.TIMEOUT], timeout=5)
    if ret:
        logging.error('retrieve images infomation from samba server fail!')
        return False
    buf = child.before
    if plt == 'HELIOS':
        image_list = re.findall(r'^\s+(helios-development)\s', buf, re.M)
        image_list += re.findall(r'^\s+(heliosr-release-\d+\.\d+)\s', buf, re.M)
        image_list += re.findall(r'^\s+(helios-cross-build-image)\s', buf, re.M)

    elif plt == 'APOLLO':
        image_list = re.findall(r'^\s+(apollo-combo-development)\s', buf, re.M)
        image_list += re.findall(r'^\s+(apollo-apollor-release-\d+\.\d+)\s', buf, re.M)
        image_list += re.findall(r'^\s+(apollo-cross-build-image)\s', buf, re.M)

    image_list.sort()
    a = len(image_list)
    while True:
        for i in xrange(a):
            print '\t%d > %s'%(i+1, image_list[i])
        index = raw_input('Input the index of images: ')
        try:
            n = int(index)
            if n==0 or n > a:
                print 'input number out of range...'
                continue
            break
        except Exception, msg:
            print 'ValueError, pls input a num...'
            print traceback.format_exc()
            continue

    target_image = image_list[n-1]
    child.expect(['.+', pexpect.TIMEOUT], timeout=5)
    child.sendline(r'l %s\\\*'%target_image)
    ret = child.expect(['\d+ blocks of size \d+\. \d+ blocks available', pexpect.TIMEOUT], timeout=5)
    buf = child.before
    version_list = re.findall(r'^\s+(\w+-\S+)\s+[A-Z]+\s', buf, re.M)
    if not version_list:
        print 'Retrieve images info fail, retry...'
        child.close()
        start()
    version_list.sort()

    x = len(version_list)
    print '\n%s'%target_image
    for i in xrange(x):
        if i < x:
            print "\t%d > %s"%(i+1, version_list[i])

    while True:
        index = raw_input('\nInput the index to start tftp flash: ')
        try:
            n = int(index)
            if n==0 or n > x:
                print 'input number out of range...'
                continue
            break
        except Exception, msg:
            print 'ValueError, pleas input a number...'
#            print traceback.format_exc()
            continue
    
    version = version_list[n-1]

    while True:
        ip = raw_input('Input dut ip address: ')
        if not re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',ip):
            print 'Not an IP address, please input an avaliable IP adderss.'
            continue
        break

    while True:
        port_s = raw_input('Input dut port number: ')
        try:
            port = int(port_s)
            break
        except Exception:
            print 'Input an avaliable port number.' 
            continue
    image_path = '//172.16.11.28/images/%s/%s'%(target_image, version)

    print 'Tftp information:'
    print '\tversion: %s'%version
    print '\tdut ip: %s'%ip
    print '\tport: %d'%port
    while True:
        input_str = raw_input('ready to go(yes/no): ')
        if input_str.startswith('y'):
            break
        if input_str.startswith('n'):
            sys.exit()
        continue
    print 'GOOD LUCK...'
    tftp_flash(ip, port, image_path)





def start():
    print 'Welcome to use auto tftp tool. \nDo simple choices before tftp start:'
    print 'Choice your platform:'
    for i in xrange(len(plt_list)):
        print '\t%d > %s'%(i+1, plt_list[i])

    while True:
        index = raw_input('Input the platform index: ')
        try:
            n = int(index)
            if n == 0 or n > len(plt_list):
                print 'input number out of range...'
                continue
            break
        except Exception, msg:
            print 'ValueError, pls input a num...'
            continue

    retrieve_images(plt_list[n-1])



if __name__ == '__main__':
    start()
