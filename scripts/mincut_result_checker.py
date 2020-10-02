# -*- coding: utf-8 -*-
"""
Created on Sat Aug 10 13:57:54 2013

@author: abaki
"""

import re


class Matcher:
    IS_CASE_SENSITIVE = re.IGNORECASE
    def __init__(self):
        self.result = None
    
    def match_start_name(self,string):
        self.result = re.match(r".*mincut for\s:\s\w+.*", string, Matcher.IS_CASE_SENSITIVE)
        return self.result        
    def match_mincut_info(self,string):
        self.result = re.match(r".*result\s:\ssize\s:\s(?P<size>\d+)\s:\schars\s:\s+(?P<chars>.*)", string, Matcher.IS_CASE_SENSITIVE)
        return self.result
    def match_result_info(self,string):
        self.result = re.match(r".*result\s:\s(?P<title>[\w ]+)\s:\s(?P<op>.+).*", string, Matcher.IS_CASE_SENSITIVE)
        return self.result
    def match_time_info(self,string):
        self.result = re.match(r".*mincut_time\s*:\s(?P<time>\d+)\s*", string, Matcher.IS_CASE_SENSITIVE)
        return self.result
    def match_time_header(self,string):
        self.result = re.match(r".*Timers.*", string, Matcher.IS_CASE_SENSITIVE)
        return self.result
        
class Result:
    def __init__(self):
        self.pair_name = ""
        self.size = ""
        self.chars = ""
        self.time = ""
        self.op_results = []
      
    def __str__(self):
        row = ''
        row = self.pair_name + ','
        row += self.time + ','
#        row += self.chars + '\n'
        row += self.size + ','
        row += ','.join(self.op_results) + '\n'
        return row

shared_result = Result()    
def extract_results(output_string, output_file, pair_name=""):
    global shared_result    
    outf = open(output_file, "w")

    matcher = Matcher()
    result = Result()
    state = 0
    for line in output_string.split('\n'):
#        print "handling: " + line
#        print " state: " + str(state)
        if state == 0:
            if not matcher.match_start_name(line):
                continue       
            result.pair_name = pair_name
            state = 1
        elif state == 1:
            if not matcher.match_mincut_info(line):
                continue
            result.size = matcher.result.group('size')
            result.chars = matcher.result.group('chars')
            state = 2
        elif state == 2:
            if matcher.match_time_header(line):
                state = 3
                continue
            if not matcher.match_result_info(line):
                continue
            result.op_results.append(matcher.result.group('title'))
#                result.op_results.append(matcher.result.group('op'))
        elif state == 3:
            if not matcher.match_time_info(line):
                continue
            result.time = matcher.result.group('time')
            state = 4
        elif state == 4:
            outf.write(result.__str__())
            shared_result = result
            result = Result()
            state = 0


    outf.close()
