
import yaml

data = {}
data['server'] = []
data['server'].append( {
    'ip': '127.0.0.1',
    'port': {'start':18080,'end':18081},
    'rules': {'snort':['snort_rules/index.rules'],
        'yara':{ 
            'namespace1':'./yara_rules/index.rule'
            }}
    } )

data = yaml.dump(data, default_flow_style=False)

f = open( 'conf.yaml', 'w')
f.write( data )
f.close()
print( data )

