import os, sys, subprocess

def main():
    try:
        with open("workdir/patch_count", 'r') as f:
            patches = set(f.read().strip('\n').split('\n'))
        # print(patches)
        with open("workdir/patch_", 'r') as f:
            patch_infos = f.read().strip('\n').split('\n')
        new_patch_infos = []
        for patch_info in patch_infos:
            patch_info = patch_info.split(' ')
            addr = patch_info[0]
            if len(patch_info)>3 and patch_info[2]=='0x0':
                avoid = patch_info[3]
            else:
                avoid = None
            pcode = patch_info[1]
            new_patch_infos.append((addr, pcode, avoid))

        nopcnt = len([i for i in new_patch_infos if i[0] in patches and i[1] == 'nop'])
        bracnt = len([i for i in new_patch_infos if i[2] and i[2] in patches and i[1] == 'jmp'])
        nopsum = len([i for i in new_patch_infos if i[1] == 'nop'])
        brasum = len([i for i in new_patch_infos if i[2] and i[1] == 'jmp'])

        sys.stdout.write("Current working directory: \033[0;44m%s\033[0m\n"% os.getcwd())

        output ='nopcnt: %d\nnopsum: %d\n(nopcnt/nopsum):%.2f%%\nbracnt: %d\nbrasum: %d\n(bracnt/brasum):%.2f%%'%(nopcnt, nopsum, nopcnt*100.0/nopsum if nopsum!=0 else 0, bracnt, brasum, bracnt*100.0/brasum if brasum!=0 else 0)
        # print(output)

        with open('workdir/patch_count_sum','w') as f:
            f.write(output+'\n')


    except IOError as e:
        print("workdir/patch_count not found, exit")
        exit(-1)

def count(path):
    p = subprocess.Popen("for dir in `ls %s`; do echo ${dir%%_*}; done" % path, shell=True, stdout=subprocess.PIPE)
    # p.wait()
    brands = set(p.stdout.read().decode().strip('\n').split('\n'))
    print(brands)
    for b in brands:
        pathall = '%s/%s'%(path, b)
        # print(os.getcwd())
        p = subprocess.Popen("cat patch_count_sum | grep \"%s_*\" -B1 -A8 2>&1"%pathall, shell=True, stdout=subprocess.PIPE)
        recv = p.stdout.read().strip(b'\n').split(b'\n')
        nopcnt = 0
        nopsum = 0
        bracnt = 0
        brasum = 0
        path_count = 0
        for i in recv:
            if b'nopcnt' in i and b"(nopcnt/nopsum)" not in i:
                try:
                    nopcnt += int(i.split(b' ')[-1])
                except:
                    nopcnt += 0
            if b'nopsum' in i and b"(nopcnt/nopsum)" not in i:
                try:
                    nopsum += int(i.split(b' ')[-1])
                except:
                    nopsum += 0
            if b'bracnt' in i and b"(bracnt/brasum)" not in i:
                try:
                    bracnt += int(i.split(b' ')[-1])
                except:
                    bracnt += 0
            if b'brasum' in i and b"(bracnt/brasum)" not in i:
                try:
                    brasum += int(i.split(b' ')[-1])
                except:
                    brasum += 0
            if b'path count' in i:
                try:
                    path_count += int(i.split(b' ')[-1])
                except:
                    path_count += 0
        print("\nPath %s has:\nnopcnt:%d\nnopsum:%d\nbracnt:%d\nbrasum:%d\npath_count:%d\n"%(pathall, nopcnt, nopsum, bracnt, brasum, path_count))
        if nopsum!=0 and brasum!=0:
            print("nopcnt/nopsum:%.2f%%\nbracnt/brasum:%.2f%%\n" % (nopcnt*100.0/nopsum, bracnt*100.0/brasum))
            print("%.2f%%(%d/%d)"%(nopcnt*100.0/nopsum, nopcnt, nopsum))
            print("%.2f%%(%d/%d)"%(bracnt*100.0/brasum, bracnt, brasum))
        print(path_count)
    
        p = subprocess.Popen("for dir in `ls -d %s*`; do ls $dir/afl_output/default/crashes/ | wc -l; done"%(pathall), shell=True, stdout=subprocess.PIPE)
        p.wait()
        crash_count = []
        for i in p.stdout.read().decode().strip('\n').split('\n'):
            if len(i)==0: continue
            if int(i)>0:
                crash_count.append(int(i)-1)
            else:
                crash_count.append(0)
        print(crash_count)
        print(sum(crash_count))

if __name__ == '__main__':
    if len(sys.argv)==1:
        main()
    else:
        count(sys.argv[1])
