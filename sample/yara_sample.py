import yara

rules = yara.compile(filepaths={
  'namespace1':'../yara_rules/index.yar'
})

#matches = rules.match(data='GET /index.html HTTP/1.1')
matches = rules.match(data='CONNECT /index.html HTTP/1.1')

for r in matches :
    print(r)
#    print(r.namespace)
    print(r.meta)
    print(r.rule)
    print(r.strings)
    print(r.tags)
