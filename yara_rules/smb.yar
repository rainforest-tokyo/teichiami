rule smb: smb {
meta: 
    honey_ip = "127.0.0.1"
    honey_port = 60023

strings: 
    $method_1 = "SMB" nocase 

condition: 
    $method_1
}
