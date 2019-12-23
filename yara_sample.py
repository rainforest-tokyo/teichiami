
import yara

rules = yara.compile(filepaths={
  'namespace1':'./rules/index.rule'
})

matches = rules.match(data='abcdefgjiklmnoprstuvwxyz')

for r in matches :
    print(r.namespace)
    print(r.meta)
    print(r.rule)
    print(r.strings)
    print(r.tags)
