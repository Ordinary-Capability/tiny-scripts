#!/usr/bin/env python
#-*- coding:utf-8-*-

import pexpect
import sys
import threading
import time
import signal
import getpass
import os
import termios
#import getpass

__author__ = 'zheng.ke@whaley.cn'

#transplant from getpass
def _raw_input(prompt="", stream=None, input=None):
    # A raw_input() replacement that doesn't save the string in the
    # GNU readline history.
    if not stream:
        stream = sys.stderr
    if not input:
        input = sys.stdin
    prompt = str(prompt)
    if prompt:
        stream.write(prompt)
        stream.flush()
    # NOTE: The Python C API calls flockfile() (and unlock) during readline.
    line = input.readline()
    if not line:
        raise EOFError
    if line[-1] == '\n':
        line = line[:-1]
    return line

#transplant from getpass
def unix_getpass(prompt='Password: ', stream=None):
    """Prompt for a password, with echo turned off.

    Args:
      prompt: Written on stream to ask for the input.  Default: 'Password: '
      stream: A writable file object to display the prompt.  Defaults to
              the tty.  If no tty is available defaults to sys.stderr.
    Returns:
      The seKr3t input.
    Raises:
      EOFError: If our input tty or stdin was closed.
      GetPassWarning: When we were unable to turn echo off on the input.

    Always restores terminal settings before returning.
    """
    fd = None
    tty = None
    try:
        # Always try reading and writing directly on the tty first.
        fd = os.open('/dev/tty', os.O_RDWR|os.O_NOCTTY)
        tty = os.fdopen(fd, 'w+', 1)
        input = tty
        if not stream:
            stream = tty
    except EnvironmentError, e:
        print 'fd except'
        # If that fails, see if stdin can be controlled.
        try:
            fd = sys.stdin.fileno()
        except (AttributeError, ValueError):
            passwd = fallback_getpass(prompt, stream)
        input = sys.stdin
        if not stream:
            stream = sys.stderr

    if fd is not None:
        passwd = None
        old = termios.tcgetattr(fd)     # a copy to save
        new = old[:]
        new[3] &= ~termios.ECHO  # 3 == 'lflags'
        tcsetattr_flags = termios.TCSAFLUSH
        if hasattr(termios, 'TCSASOFT'):
            tcsetattr_flags |= termios.TCSASOFT
        try:
            termios.tcsetattr(fd, tcsetattr_flags, new)
            passwd = _raw_input(prompt, stream, input=input)
        finally:
            termios.tcsetattr(fd, tcsetattr_flags, old)
            stream.flush()  # issue7208
    return passwd

def get_buffer():
    global run
    global child
    while run:
        byte = child.read(1)
        if byte == '\n':
            sys.stdout.write(byte + '[' + str(time.time()) + ']  ')
            sys.stdout.flush()
        else:
            sys.stdout.write(byte)
            sys.stdout.flush()

def signal_handler(signum, frame):
    global child
    if signum == signal.SIGINT:
        child.sendcontrol('c')

run = True
signal.signal(signal.SIGINT, signal_handler)
socat_cmd = 'socat '+ sys.argv[1] + ' ' + sys.argv[2]
child = pexpect.spawn(socat_cmd,timeout = 300)
td = threading.Thread(target=get_buffer)
td.daemon = True
td.start()

while run:
    child.sendline(unix_getpass(''))

