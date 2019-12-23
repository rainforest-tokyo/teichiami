
import yara

rules = yara.compile(filepaths={
  'namespace1':'./yara_rules/index.rule'
})

matches = rules.match(data='GET /index.html HTTP/1.1')

for r in matches :
    print(r.namespace)
    print(r.meta)
    print(r.rule)
    print(r.strings)
    print(r.tags)
