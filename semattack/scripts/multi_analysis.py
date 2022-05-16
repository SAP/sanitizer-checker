#!/usr/bin/python3

import os, sys, time
import threading
from concurrent.futures import ThreadPoolExecutor

#/work/SemRep/SemRep/src/multiattack --fieldname x --target test/broken_sanitizer.dot --output data/test_output/


def get_files(directory):
    files = []
    print("Adding files in", directory)
    for file in os.listdir(directory):
        if file.endswith(".dot"):
            print("Adding file: ", file)
            files.append(os.path.join(directory, file))
    return files

def execute_sem_attack(input_file, output_base):
    out_dir = os.path.join(output_base, input_file)
    print("Launching analysis of ", input_file, " out: ", out_dir)
    if not os.path.exists(out_dir):
        print("Making dir:", out_dir)
        os.makedirs(out_dir)
    logfile = os.path.join(out_dir, "output.log")
    cmd = "/work/SemRep/SemRep/src/multiattack --fieldname x" + \
          " --target " + input_file + \
          " --output " + output_base + \
          " > " + logfile
    print("CMD: ", cmd)
    os.system(cmd)
    print("Analysis of ", input_file, "done!")

def print_status(poolx):
    print()
    print("Pool status:")
    print('pid:', os.getpid())
    print('pending:', poolx._work_queue.qsize(), 'jobs')
    print('threads:', len(poolx._threads))
    print()
    return poolx._work_queue.qsize()
    
def launch_analysis(input_dir, output_dir):
    print("Analysing files in", input_dir)
    input_files = get_files(input_dir)
    executor = ThreadPoolExecutor(max_workers = 16)
    for f in input_files:
        print(f)
        executor.submit(execute_sem_attack, f, output_dir)
    while print_status(executor) > 0:
        time.sleep(5)
    executor.shutdown(wait=True)
    print("All done!")

def main():
    launch_analysis(sys.argv[1], sys.argv[2])

if __name__ == '__main__':
    main()
