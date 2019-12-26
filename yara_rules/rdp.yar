rule rdp: rdp {
meta: 
    honey_ip = "127.0.0.1"
    honey_port = 63389

strings: 
    $method_1 = "mstshash" nocase 

condition: 
    $method_1
}
