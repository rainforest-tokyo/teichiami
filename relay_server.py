#!/usr/bin/env python

from __future__ import print_function
from contextlib import contextmanager
import time
import yaml

import socket
import select

import chardet
import logging
import threading

import yara
import snortsig

logging.basicConfig(level=logging.DEBUG, format='%(threadName)s: %(message)s')
logging.getLogger('chardet.charsetprober').setLevel(logging.INFO)

class ConnectionClass():
    def __init__(self):
        self.client_connection = None
        self.honey_connection = None
        self.request = ""
        self.response = ""
        self.buffer = ""
        self.mutch_flag = False

    def setClient( self, connection ):
        self.client_connection = connection

    def getClient( self ):
        return self.client_connection
        
    def setHoney( self, connection ):
        self.honey_connection = connection

    def getHoney( self ):
        return self.honey_connection
        
    def addRequest( self, data ) :
        self.request += data

    def getRequest( self ) :
        return self.request

    def doneRequest( self ) :
        self.request = ""

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

@contextmanager
def socketcontext(*args, **kwargs):
    """Context manager for a socket."""
    s = socket.socket(*args, **kwargs)
    try:
        yield s
    finally:
        fd = s.fileno()
        print("Close socket")
        print( fd )
        s.close()

@contextmanager
def epollcontext(*args, **kwargs):
    """Context manager for an epoll loop."""
    e = select.epoll()
    e.register(*args, **kwargs)
    try:
        yield e
    finally:
        print("\nClose epoll loop")
        e.unregister(args[0])
        e.close()

def connenct_to_honey(host, port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    client.settimeout(1.0)
    return client

def init_connection(server, connections, epoll):
    """Initialize a connection."""
    con, address = server.accept()
    con.setblocking(0)

    fd = con.fileno()
    epoll.register(fd, select.EPOLLIN)

    obj = ConnectionClass()
    obj.setClient( con )
    connections[fd] = obj

def receive_request(fileno, connections, epoll, rules):
    obj = connections[fileno]
    con = obj.getClient()

    # Get Recv Client Info
    recv_ip = con.getsockname()[0]
    recv_port = con.getsockname()[1]
    logging.debug("recv port [%d][%s][%d]"%(fileno, recv_ip, recv_port))

    # Set Honey Info
    mutch_flag = obj.getMutchFlag()
    honey_ip = rules['default']['ip']
    honey_port = rules['default']['port']

    # Recv Data
    tmp = con.recv(4096)
    # Empty Check: empty -> close socket
    if tmp == "" :
        obj.doneRequest()
        close_request(fileno, connections)
        return

    obj.addRequest( tmp )

    # ASCII code Check
    ascii_check = obj.getRequest( )
    if (len(ascii_check) > 0) and (ord(ascii_check[len(ascii_check)-1]) == 0x0) :
        ascii_check = ascii_check[0:len(ascii_check)-1]
    before_len = len( ascii_check )
    ascii_check = ascii_check.strip()
    after_len = len( ascii_check )

#    poll_mode = select.EPOLLOUT
    send_to_honey = True

    str_status = ascii_check.isalnum()
    if str_status :
        logging.debug("recv request (TEXT) [%d][%s]"%(fileno, ascii_check))
        if mutch_flag == False :
            if before_len == after_len :
                logging.debug("not found New LINE")
#                poll_mode = select.EPOLLIN
                send_to_honey = False
            else :
                if ord(tmp[len(tmp)-1]) == 0x0 :
                    tmp = tmp[0:len(tmp)-1]
#                tmp += '\r\n'
    else :
        logging.debug("recv request (BIN) [%d][%s]"%(fileno, tmp))

    poll_mode = select.EPOLLOUT + select.EPOLLIN

    # Empty Check: empty -> close socket
#    if tmp == "" :
#        obj.doneRequest()
#        close_request(fileno, connections)
#        return

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
        logging.debug("DEF hony port [%d][%s][%d]"%(fileno, honey_ip, honey_port))
        obj.setHoney(current)

    # Send To Honey
    try :
        current.send( tmp )
        logging.debug("Send hony [%d][%s][%d][%d][%s]"%(fileno, honey_ip, honey_port, len(tmp), tmp))
        obj.doneRequest()
    except :
        close_request(fileno, connections)

    # Recv From Honey
#    if poll_mode == select.EPOLLOUT :
#    if send_to_honey == True :
#        logging.debug("POLL OUT MODE")
#        response = current.recv(4096)
#        logging.debug("Recv hony [%d][%s][%d][%d][%s]"%(fileno, honey_ip, honey_port, len(response), response))
#        obj.addResponse( response )
#    else :
#        logging.debug("POLL IN MODE")

    try :
        #epoll.modify(fileno, select.EPOLLOUT)
        epoll.modify(fileno, poll_mode)
    except :
        close_request(fileno, connections)

def send_response(fileno, connections, epoll):
    poll_mode = select.EPOLLOUT + select.EPOLLIN
    #poll_mode = select.EPOLLIN

    #byteswritten = connections[fileno].send(responses[fileno])
    obj = connections[fileno]
    current = obj.getHoney()
    try :
        response = current.recv(4096)
        logging.debug("Recv hony [%d][%d][%s]"%(fileno, len(response), response))
        obj.addResponse( response )
        if response == "" :
            close_request(fileno, connections)
    except :
        return

    try :
        res_data = obj.getResponse()
        logging.debug("send response [%d][%s]"%(fileno, res_data))
        obj.getClient().send( res_data )

        # 
        #epoll.modify(fileno, select.EPOLLIN)
        epoll.modify(fileno, poll_mode)
    except :
        try :
            close_request(fileno, connections)
        except :
            pass

def close_request(fileno, connections):
    try :
        obj = connections[fileno]
    except :
        return

    logging.debug("close [%d]"%(fileno))
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

def run_server(socket_options, address, rules):
    """Run a simple TCP server using epoll."""
    try:
        logging.debug("start")
        with socketcontext(*socket_options) as server, epollcontext(server.fileno(), select.EPOLLIN) as epoll:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(address)
            server.listen(5)
            server.setblocking(0)
            server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            logging.debug("Listening")

            connections = {}
            server_fd = server.fileno()

            while True:
                events = epoll.poll(1)

                for fileno, event in events:
                    if fileno == server_fd:
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

def run_server_thread( conf_filename ):
    f = open(conf_filename, "r+")
    conf_data = yaml.load(f)
    f.close()

    for server in conf_data['server'] :
        print( server );

        # load SNORT Rules
        server['rules']['snort_data'] = load_snort( server )
        #print(server['rules']['snort_data'])

        # load YARA Rules
        server['rules']['yara_data'] = load_yara( server )
        #print(server['rules']['yara_data'])

        for port in range(server['port']['start'], server['port']['end']):
            t1 = threading.Thread(name='port %d'%(port), 
                    target=run_server, 
                    args=([socket.AF_INET, socket.SOCK_STREAM], (server['ip'], port), server['rules']))
            t1.start()

if __name__ == '__main__':
    run_server_thread( './conf.yaml' )


