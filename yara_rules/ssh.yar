rule ssh: ssh {
meta: 
    honey_ip = "127.0.0.1"
    honey_port = 60022

strings: 
    $method_1 = "SSH-" nocase 

condition: 
    $method_1
}
