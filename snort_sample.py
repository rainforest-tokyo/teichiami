
import snortsig

ss = snortsig.SnortSig()
ss.fromfile( "snort_rules/index.rules" )

for item in ss.getall() :
    print("%s[%s] -> %s[%s]" % (item['src'], item['src_port'][0], item['dst'], item['dst_port'][0]))


