from multiprocessing import Pool
import os, time, random, json, signal
import shutil

with open('evaluation_set/device_info.json','r') as f:
    cont = json.load(f)

def worker(c):
    os.system("./run.sh %s %s %s"%(c['deviceURI'], c['arch'], c['base']))


po = Pool(8)

def sigint_handler(signalnum, handler):
    print("RECV SIGINT or SIGTERM or SIGKILL signal, stop all subprocesses")
    po.terminate()
    exit(0)
signal.signal(signal.SIGINT, sigint_handler)
print("----start----")

dirs = next(os.walk("findtrace_output"))[1]
print('dirs: %r'%dirs)
for c in cont:
    #if "AC11" not in c['deviceURI']:
    #    continue
    filename = os.path.basename(c['deviceURI'])
    if filename+'_result' not in dirs:
        print("apply_async for c: %r"%c)
        po.apply_async(worker,(c,))

po.close()
po.join()
print("-----end-----")