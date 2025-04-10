import os, json

basedir = os.path.dirname(__file__)

if not os.path.exists(os.path.join(basedir, 'logs')): os.mkdir(os.path.join(basedir, 'logs'))

monitor_json = os.path.join(basedir, 'logs', 'monitor__get__attributes__.json')
monitor_dict = {}
if os.path.exists(monitor_json):
    with open(monitor_json, 'r') as f:
        monitor_dict = json.load(f)
        
def monitor__get__attributes__(self, name: str):
    resp = object.__getattribute__(self, name)
    key = repr(object.__getattribute__(self, "__class__"))
    
    if key not in monitor_dict: 
        monitor_dict[key] = {}
    if name not in monitor_dict[key]:
        monitor_dict[key].update({
            name: repr(resp)
        })
        with open(monitor_json, 'w') as f:
            json.dump(monitor_dict, f)
    
    return resp
    