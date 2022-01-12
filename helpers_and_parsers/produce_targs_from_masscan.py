import json

with open("masscan.webports.json") as _file:
    _file = _file.read().strip()
    _json = json.loads(_file)
    for target in _json:
        #target = target
        for port in target["ports"]:
#            print(port["port"])
            print(target["ip"] + ":" + str(port["port"]))
