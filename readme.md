Install Package

- [ ] apt install yara
- [ ] pip install yara-python
- [ ] pip install snortsig
- [ ] pip install pyparsing

起動

```
usage: relay_server.py [-h] [-c CONFIG] [-d]

Packet Forwarder

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        config file
  -d, --debug           debug mode
```

CONFIGファイル

```
log: # ログの出力先
  path: "/var/log/autonapt"
  filename: "rfpf_%Y%m%d.json"

server:
- ip: 0.0.0.0　＃監視IPアドレス
  port:
    start: 22　＃監視 開始port番号
    end: 50000　＃監視 終了port番号
  rules:
    default:＃プロトコルが判定できない場合に利用するサーバ(ハニーなど)
        ip: 127.0.0.1
        port: 60023
    snort:　＃TCPヘッダーを確認して利用するサーバを決定する format:SNORT
        - ./snort_rules/index.rules
    yara:　＃ペイロードを確認して利用するサーバを決定する format:YARA
        namespace1: ./yara_rules/index.yar
```

SNORT ルール

```
# 受信 PORT情報 -> 送信先 IP/PORT
alert tcp any 22 -> 127.0.0.1 60022 ( gid:100; sid:1001; msg:"SSH Forward"; )
alert tcp any 2222 -> 127.0.0.1 60022 ( gid:100; sid:1002; msg:"SSH Forward"; )
```

YARA ルール

```
rule http_get: http {
meta: #送信先　IP/PORT
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
```





