import os
import sys

current_dir = os.path.abspath(os.path.dirname(__file__))
res_map = {}
for name in os.listdir(current_dir):
    if name not in res_map:
        res_map[name] = 0
    if name.endswith('_result'):
        target_dir = os.path.join(current_dir,name)
        for filename in os.listdir(target_dir):
            if filename.startswith('connect_'):
                filepath = os.path.join(target_dir,filename)
                with open(filepath,'r') as f:
                    content = f.read()
                    res_map[name] += len(content.split('\n'))-1

new_map = {}
for key,val in res_map.items():
    if val != 0:
        new_map[key] = val
for key,val in new_map.items():
    print("{}:{}".format(key,val))