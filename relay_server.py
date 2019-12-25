#!/usr/bin/env python

from __future__ import print_function
from contextlib import contextmanager
import os
import time
import yaml
import json
import string
import datetime

import socket
import select

import chardet
import logging
import threading

import yara
import snortsig

logging.basicConfig(level=logging.DEBUG, format='%(threadName)s: %(message)s')
logging.getLogger('chardet.charsetprober').setLevel(logging.INFO)

gLogFilename = ""

#--------------------------------------
# Connection Infomation
class ConnectionClass():
    def __init__(self):
        self.client_connection = None
        self.honey_connection = None

        self.mutch_flag = False
        self.alert_flag = False
        self.add_delimit_flag = True

        self.request = ""
        self.request_printable = ""
        self.response = ""
        self.buffer = ""

        self.remote_ip = ""
        self.remote_port = 0
        self.server_ip = ""
        self.server_port = 0

    def setRemote( self, ip, port ):
        self.remote_ip = ip
        self.remote_port = port

    def getRemoteIp( self ):
        return self.remote_ip

    def getRemotePort( self ):
        return self.remote_port

    def setServer( self, ip, port ):
        self.server_ip = ip
        self.server_port = port

    def getServerIp( self ):
        return self.server_ip

    def getServerPort( self ):
        return self.server_port

    def setClient( self, connection ):
        self.client_connection = connection

    def getClient( self ):
        return self.client_connection
        
    def setHoney( self, connection ):
        self.honey_connection = connection

    def getHoney( self ):
        return self.honey_connection
        
    def addRequest( self, data ) :
        if (len(data) > 0) and (ord(data[len(data)-1]) == 0x0) :
            data = data[0:len(data)-1]
        self.request += data
        p_data = strings(data)
        if p_data != None :
            self.request_printable += p_data
            self.add_delimit_flag = True

    def getRequest( self ) :
        return self.request

    def addRequestPrintableDelimit( self ) :
        if self.add_delimit_flag :
            self.request_printable += ','
            self.add_delimit_flag = False

    def getRequestPrintable( self ) :
        return self.request_printable

    def doneRequest( self ) :
        self.request = ""
        self.request_printable = ""

    def addResponse( self, data ) :
        self.buffer = data
        self.response += data

    def getResponse( self ) :
        tmp = self.buffer
        self.buffer = ""
        return tmp

    def setMutchFlag( self, flag ) :
        self.mutch_flag = flag

    def getMutchFlag( self ) :
        return self.mutch_flag

    def setAlertFlag( self, flag ) :
        self.alert_flag = flag

    def getAlertFlag( self ) :
        return self.alert_flag
#--------------------------------------

#--------------------------------------
# get printable strings
def strings(text, min=1):
    result = ""
    for c in text:
        if c.isalnum() or c.isspace() or c in [':','.','/','?','%''=']:
#        if c in string.printable:
            result += c

    if len(result) >= min:
        result = result.replace('\r','\\r')
        result = result.replace('\n','\\n')
        return result
#--------------------------------------

#--------------------------------------
# connect to Backend Honey
def connenct_to_honey(host, port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    client.settimeout(1.0)
    return client
#--------------------------------------

#--------------------------------------
# Accept Socket
def init_connection(server, connections, epoll):
    """Initialize a connection."""
    con, address = server.accept()
    con.setblocking(0)

    fd = con.fileno()
    epoll.register(fd, select.EPOLLIN)

    obj = ConnectionClass()
    obj.setClient( con )
    connections[fd] = obj

    obj.setRemote( con.getpeername()[0], con.getpeername()[1])
    obj.setServer( con.getsockname()[0], con.getsockname()[1])
#--------------------------------------

#--------------------------------------
# Recv from Attacker
def receive_request(fileno, connections, epoll, rules):
    obj = connections[fileno]
    con = obj.getClient()

    # Get Recv Client Info
    recv_ip = obj.getServerIp()
    recv_port = obj.getServerPort()
#    logging.debug("recv port [%d][%s][%d]"%(fileno, recv_ip, recv_port))

    # Set Honey Info
    mutch_flag = obj.getMutchFlag()
    honey_ip = rules['default']['ip']
    honey_port = rules['default']['port']

    # Recv Data
    tmp = con.recv(4096)
    # Empty Check: empty -> close socket
    if tmp == "" :
        close_request(fileno, connections)
        return

    obj.addRequest( tmp )

    # ASCII code Check
    ascii_check = obj.getRequest( )
    before_len = len( ascii_check )
    ascii_check = ascii_check.strip()
    after_len = len( ascii_check )

    send_to_honey = True

    str_status = ascii_check.isalnum()
    if str_status :
#        logging.debug("recv request (TEXT) [%d][%s]"%(fileno, ascii_check))
        if mutch_flag == False :
            if before_len == after_len :
#                logging.debug("not found New LINE")
                send_to_honey = False
            else :
                if ord(tmp[len(tmp)-1]) == 0x0 :
                    tmp = tmp[0:len(tmp)-1]
#    else :
#        logging.debug("recv request (BIN) [%d][%s]"%(fileno, tmp))

    poll_mode = select.EPOLLOUT + select.EPOLLIN

    # Check Snort Rule
    if mutch_flag == False :
        for item in rules['snort_data'] :
            if (item['src'] == 'any') and (item['src_port'] == 'any') :
                continue

            if ((('any' in item['src']) or (recv_ip in item['src'])) \
            and (('any' in item['src_port']) or (str(recv_port) in item['src_port']))) :
                honey_ip = item['dst'][0]
                honey_port = int(item['dst_port'][0])

                current = obj.getHoney()
                if current != None :
                    try :
                        current.detach()
                    except :
                        current.close()

                current = conenct_to_honey( honey_ip, honey_port )
                logging.debug("SNORT hony port [%d][%s][%d]"%(fileno, honey_ip, honey_port))
                obj.setHoney(current)
                mutch_flag = True
                obj.setMutchFlag( mutch_flag )
                break

    # Check YARA Rule
    if mutch_flag == False:
        req_data = obj.getRequest()
        matches = rules['yara_data'].match(data=req_data)
        for r in matches :
            honey_ip = r.meta['honey_ip']
            honey_port = r.meta['honey_port']

            current = obj.getHoney()
            if current != None :
                try :
                    current.detach()
                except :
                    current.close()

            current = connenct_to_honey( honey_ip, honey_port )
            logging.debug("YARA hony port [%d][%s][%d]"%(fileno, honey_ip, honey_port))
            obj.setHoney(current)
            mutch_flag = True
            obj.setMutchFlag( mutch_flag )
            break

    # Connect To Honey
    current = obj.getHoney()
    if current == None :
        current = connenct_to_honey( honey_ip, honey_port )
        #logging.debug("DEF hony port [%d][%s][%d]"%(fileno, honey_ip, honey_port))
        obj.setHoney(current)

    # Send To Honey
    try :
        current.send( tmp )
        #logging.debug("Send hony [%d][%s][%d][%d][%s]"%(fileno, honey_ip, honey_port, len(tmp), tmp))
    except :
        close_request(fileno, connections)

    try :
        epoll.modify(fileno, poll_mode)
    except :
        close_request(fileno, connections)
#--------------------------------------

#--------------------------------------
# Send to Attacker
def send_response(fileno, connections, epoll):
    poll_mode = select.EPOLLOUT + select.EPOLLIN
    #poll_mode = select.EPOLLIN

    #byteswritten = connections[fileno].send(responses[fileno])
    obj = connections[fileno]
    obj.addRequestPrintableDelimit()
    current = obj.getHoney()
    try :
        response = current.recv(4096)
        #logging.debug("Recv hony [%d][%d][%s]"%(fileno, len(response), response))
        obj.addResponse( response )
        if response == "" :
            close_request(fileno, connections)
    except :
        return

    try :
        res_data = obj.getResponse()
        obj.getClient().send( res_data )

        epoll.modify(fileno, poll_mode)
    except :
        try :
            close_request(fileno, connections)
        except :
            pass
#--------------------------------------

#--------------------------------------
# Close Socket
def close_request(fileno, connections):
    global gLogFilename

    try :
        obj = connections[fileno]
    except :
        return

    orig_data = obj.getRequest()
    printable_data = obj.getRequestPrintable()
    obj.doneRequest()

    recv_ip = obj.getServerIp()
    recv_port = obj.getServerPort()
    send_ip = obj.getRemoteIp()
    send_port = obj.getRemotePort()

    dt_now = datetime.datetime.now()
    log_data = {
        "timestamp": dt_now.strftime('%Y-%m-%d %H:%M:%S'),
        "event_type": "autonapt",
        "src_ip": send_ip,
        "src_port": send_port,
        "dest_ip": recv_ip,
        "dest_port": recv_port,
        "proto": "TCP",
        "flow": {
          "bytes_toserver": len(orig_data),
        },
        "payload": orig_data,
        "payload_printable": printable_data
      }

    filename = dt_now.strftime( gLogFilename )
    f = open(filename, 'a')
    json.dump(log_data, f)
    f.close()

    #logging.debug("close [%d]"%(fileno))
    # close
    try :
        obj.getClient().detach()
    except :
        try :
            obj.getClient().close()
        except :
            pass
        
    current = obj.getHoney()
    if current == None :
        try :
            current.detach()
        except :
            try :
                obj.getClient().close()
            except :
                pass

    del connections[fileno]
#--------------------------------------

#--------------------------------------
# Run Socket Server
def run_server(ip, bind_start, bind_end, rules):
    server_sockets = {}
    connections = {}
    try:
        logging.debug("Init Socket and EPOLL [%s]"%(ip))
        epoll = select.epoll()
        for port in range(bind_start, bind_end):
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try :
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind((ip, port))
                server.listen(5)
                server.setblocking(0)
                server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                logging.debug("Listening [%s:%d]"%(ip,port))

                fd = server.fileno()
                epoll.register( fd, select.EPOLLIN )
                server_sockets[fd] = server
            except :
                logging.debug("Socket Init Exception [%s:%d]"%(ip, port))

        logging.debug("Init Done Wait EPOLL [%s]"%(ip))
        while True:
            events = epoll.poll(1)

            for fileno, event in events:
                if fileno in server_sockets:
                    logging.debug("request [%d][%s]"%(fileno, "select.CONNECT"))
                    server = server_sockets[ fileno ]
                    init_connection(server, connections, epoll)
                elif event & select.EPOLLIN:
                    logging.debug("request [%d][%s]"%(fileno, "select.EPOLLIN"))
                    receive_request(fileno, connections, epoll, rules)
                elif event & select.EPOLLOUT:
                    logging.debug("request [%d][%s]"%(fileno, "select.EPOLLOUT"))
                    send_response(fileno, connections, epoll)
                elif event & select.EPOLLRDHUP:
                    logging.debug("request [%d][%s]"%(fileno, "select.EPOLLRDHUP"))
                    close_request(fileno, connections)
                elif event & select.EPOLLERR:
                    logging.debug("request [%d][%s]"%(fileno, "select.EPOLLERR"))
                    close_request(fileno, connections)
                elif event & select.EPOLLHUP:
                    logging.debug("request [%d][%s]"%(fileno, "select.EPOLLHUP"))
                    close_request(fileno, connections)
            time.sleep(0.5)

    except KeyboardInterrupt as e:
        print("Shutdown")

    finally:
        logging.debug("Finally EPOLL [%s]"%(ip))
        for fd in server_sockets :
            server = server_sockets[fd]
            try :
                epoll.unregister(fd)
            except :
                pass
            try :
                server.close()
            except :
                pass
        epoll.close()
#--------------------------------------

#--------------------------------------
# Load Config File
def load_yara( conf ):
    return yara.compile(filepaths=conf['rules']['yara'])

def load_snort( conf ):
    ss = snortsig.SnortSig()
    for filename in conf['rules']['snort'] :
        ss.fromfile( filename )

    ret = []
    for item in ss.getall() :
        ret.append( {
            "src": item['src'],
            "src_port": item['src_port'],
            "dst": item['dst'],
            "dst_port": item['dst_port'] 
            } )

    return ret
#--------------------------------------

#--------------------------------------
# Main
def run_server_thread( conf_filename ):
    global gLogFilename

    f = open(conf_filename, "r+")
    conf_data = yaml.load(f)
    f.close()

    gLogFilename = os.path.join( conf_data['log']['path'], conf_data['log']['filename'] )

    for server in conf_data['server'] :
        print( server );

        # load SNORT Rules
        server['rules']['snort_data'] = load_snort( server )
        #print(server['rules']['snort_data'])

        # load YARA Rules
        server['rules']['yara_data'] = load_yara( server )
        #print(server['rules']['yara_data'])

        bind_start = server['port']['start']
        bind_end = server['port']['end']
        t1 = threading.Thread(name='port %d->%d'%(bind_start, bind_end), 
                target=run_server, 
                args=(server['ip'], bind_start, bind_end, server['rules']))
        t1.start()

#--------------------------------------

if __name__ == '__main__':
    run_server_thread( './conf.yaml' )

