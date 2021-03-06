rule http_get: http {
meta: 
    honey_ip = "127.0.0.1"
    honey_port = 65082
    //honey_port = 80

strings: 
    $method_1 = "GET" nocase 
    $method_2 = "HEAD" nocase 
    $method_3 = "POST" nocase 
    $method_4 = "OPTIONS" nocase 
    $method_5 = "PUT" nocase 
    $method_6 = "DELETE" nocase 
    $method_7 = "TRACE" nocase 
    $method_8 = "PATCH" nocase 
    $method_9 = "LINK" nocase 
    $method_10 = "UNLINK" nocase 
    $method_11 = "CONNECT" nocase 
    $http = "HTTP" nocase 

condition: 
    ($method_1 or $method_2 or $method_3 or $method_4 
     or $method_5 or $method_6 or $method_7 or $method_8 
     or $method_9 or $method_10 or $method_11) 
     and $http
}
