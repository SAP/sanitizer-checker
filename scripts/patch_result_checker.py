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
    
    def match_dot_header_regex(self,string):
        self.result = re.match(r"digraph MONA_DFA {\s*", string, Matcher.IS_CASE_SENSITIVE)
        return self.result
        
    def match_dot_footer_regex(self,string):
        self.result = re.match(r"}", string, Matcher.IS_CASE_SENSITIVE)
        return self.result
    def match_field_name(self,string):
        self.result = re.match(r".*Starting Analysis for:\s(?P<field_name>\w+)\s.*", string, Matcher.IS_CASE_SENSITIVE)
        return self.result        
    def match_peak_value(self,string):
        self.result = re.match(r".*peak\s:\s(?P<op_name>\w+)\s:\sstates\s+(?P<states>\d+)\s:\sbddnodes\s+(?P<bddnodes>\d+).*", string, Matcher.IS_CASE_SENSITIVE)
        return self.result
    def match_result_header(self,string):
        self.result = re.match(r".*OVERALL RESULT for:\s(?P<field_name>\w+)\s.*", string, Matcher.IS_CASE_SENSITIVE)
        return self.result
    def match_reference_filename(self,string):
        self.result = re.match(r".*Reference:.*/(?P<file_name>\w+\.dot).*", string, Matcher.IS_CASE_SENSITIVE)
        return self.result
        
    def match_target_filename(self,string):
        self.result = re.match(r".*Target:.*/(?P<file_name>\w+\.dot).*", string, Matcher.IS_CASE_SENSITIVE)
        return self.result
        
    def match_patch_result(self,string):
        self.result = re.match(r".*generated.*", string, Matcher.IS_CASE_SENSITIVE)
        return self.result
    def match_vp_filename(self, string):
        self.result = re.match(r".*file\s:\s(?P<vp_auto_file>.*validation_patch_dfa_with_MONA_transitions\.dot).*", string, Matcher.IS_CASE_SENSITIVE)
        return self.result
    def match_lp_filename(self, string):
        self.result = re.match(r".*file\s:\s(?P<lp_auto_file>.*length_patch_dfa_with_MONA_transitions\.dot).*", string, Matcher.IS_CASE_SENSITIVE)
        return self.result
    def match_sp_filename(self, string):
        self.result = re.match(r".*file\s:\s(?P<sp_auto_file>.*sanitization_patch_dfa_with_MONA_transitions\.dot).*", string, Matcher.IS_CASE_SENSITIVE)
        return self.result
    def match_refsink_filename(self, string):
        self.result = re.match(r".*file\s:\s(?P<refsink_auto_file>.*reference_dfa_with_MONA_transitions\.dot).*", string, Matcher.IS_CASE_SENSITIVE)
        return self.result
    def match_patch_size(self,string):
        self.result = re.match(r".*size.*states\s+(?P<states>\d+).*bddnodes\s+(?P<bddnodes>\d+).*", string, Matcher.IS_CASE_SENSITIVE)
        return self.result
    def match_validation_patch_info(self,string):
        self.result = re.match(r".*Validation Patch Analysis Info.*", string, Matcher.IS_CASE_SENSITIVE)
        return self.result 
    def match_sanitization_patch_info(self,string):
        self.result = re.match(r".*Sanitization Patch Analysis Info.*", string, Matcher.IS_CASE_SENSITIVE)
        return self.result
    def match_time_info(self,string):
        self.result = re.match(r".*time\s:\s(?P<title>[\w ]+)\s:\s(?P<time>\d+)\s*", string, Matcher.IS_CASE_SENSITIVE)
        return self.result
    def match_operations_info(self,string):
        self.result = re.match(r".*Stranger Automaton Operations Info.*", string, Matcher.IS_CASE_SENSITIVE)
        return self.result 
    def match_operations_details(self,string):
        self.result = re.match(r"\s*(?P<op_name>\w+)\s:\s#(?P<count>\d+)\s:\s(?P<time>\d+)\s*", string, Matcher.IS_CASE_SENSITIVE)
        return self.result
        
    def match_phase_info(self,string):
        self.result = re.match(r".*\s+(?P<phase>\w+)\s+ANALYSIS PHASE\.+.*", string, Matcher.IS_CASE_SENSITIVE)
        return self.result
    def match_length_info(self,string):
        self.result = re.match(r".*length:\s*(?P<length>\d+)\s*", string, Matcher.IS_CASE_SENSITIVE)
        return self.result
    def match_length_info_end(self,string):
        self.result = re.match(r".*:\s*\d+us\s*", string, Matcher.IS_CASE_SENSITIVE)
        return self.result



class Header:
    def __init__(self):
        self.titles = ['field name', 'reference', 'target','validation patch', 'length patch', 'sanitization patch', 'vp #bdds', 'lp #bdds', 'sp #bdds', 'peak #vp bdds', 'peak #lp bdds', 'peak #sp bdds'] 
        self.validation_time_title = []
        self.sanitization_time_title = []
        self.operation_name = []
    def __str__(self):
        row = ','.join(self.titles) + ','
        row += ','.join(self.validation_time_title) + ','
        row += ','.join(self.sanitization_time_title) + ','
        row += ','.join(self.operation_name) + '\n'
        return row
        
class Result:
    def __init__(self):
        self.field_name = ""
        self.reference_filename = ""
        self.target_filename = ""
        self.is_validation_patch_required = ""
        self.vp_filename = ""
        self.validation_patch_states = 0
        self.validation_patch_bddnodes = 0
        self.is_length_patch_required = ""
        self.lp_filename = ""
        self.length_patch_states = 0
        self.length_patch_bddnodes = 0
        self.is_sanitization_patch_required = ""
        self.sp_filename = ""
        self.refsink_filename = ""
        self.sanitization_patch_states = 0
        self.sanitization_patch_bddnodes = 0
        self.validation_time_title = []
        self.validation_time = []
        self.sanitization_time_title = []
        self.sanitization_time = []
        self.operation_name = []
        self.operation_details = []
        self.peak_name = []
        self.peak_states = []
        self.peak_bddnodes = []    
        self.vp_peak_bdds = [0]
        self.lp_peak_bdds = [0]
        self.sp_peak_bdds = [0]
        self.length_info = ""
    def __str__(self):
        row = self.field_name + ','
        row += self.reference_filename + ','
        row += self.target_filename + ','
        row += self.is_validation_patch_required + ','
        row += self.is_length_patch_required + ','
        row += self.is_sanitization_patch_required + ','
#        row += self.validation_patch_states + ','
        row += str(self.validation_patch_bddnodes) + ','
#        row += self.length_patch_states + ','
        row += str(self.length_patch_bddnodes) + ','
#        row += self.sanitization_patch_states + ','
        row += str(self.sanitization_patch_bddnodes) + ','
        row += self.get_peak_values() + ','
        row += ','.join(self.validation_time) + ','
        row += ','.join(self.sanitization_time) + ','
        row += ','.join(self.operation_details) + '\n'
        return row
    
    def get_peak_str(self):
        max_state = max(self.peak_states)
        max_bddnode = max(self.peak_bddnodes)
        max_state_bddnodes = []
        for i,v in enumerate(self.peak_states):
            if v == max_state:
                max_state_bddnodes.append(self.peak_bddnodes[i])
                
        max_state__bddnode = max(max_state_bddnodes)
        
        max_bddnode_states = []
        for i,v in enumerate(self.peak_bddnodes):
            if v == max_bddnode:
                max_bddnode_states.append(self.peak_states[i])
                
        max_bddnode__state = max(max_bddnode_states)
        return     str(max_state) + ',' + str(max_state__bddnode) + ',' + str(max_bddnode__state) + ',' + str(max_bddnode)
    
    def get_peak_values(self):
        max_vp_bdd = max(self.vp_peak_bdds)
        max_lp_bdd = max(self.lp_peak_bdds)
        max_sp_bdd = max(self.sp_peak_bdds)
        
        return str(max_vp_bdd) + ',' + str(max_lp_bdd) + ',' + str(max_sp_bdd) 
        
    def get_peak_csv(self):
#        max_state = max(self.peak_states)
        max_bddnode = max(self.peak_bddnodes)
#        return self.length_info + ','+ str(max_bddnode) + '\n'
        return str(max_bddnode) + '\n'
        
shared_results = Result()

def extract_results(output_string, output_file, mode="w"):
    global shared_results    
    header = Header()    
    outf = open(output_file, mode)

    matcher = Matcher()
    result = Result()
    state = 0
    phase = 1 # 3 phases: 1 validation, 2 sanitization, 3 length
    for line in output_string.split('\n'):
        #print "Handling : " + line + " state: " + str(state)
        if matcher.match_phase_info(line):
            name = matcher.result.group('phase')
            if name == 'VALIDATION':
                phase = 1
            elif name == 'SANITIZATION':
                phase = 2
            else:
                phase = 3
        
        if state == 0:
            if not matcher.match_field_name(line):
                continue          
            result.field_name = matcher.result.group('field_name')
            state = 1
        elif state == 1:
            if matcher.match_result_header(line):
                state = 2
                continue
            elif not matcher.match_peak_value(line):
                continue
#                result.peak_name.append(matcher.result.group('op_name'))
#                result.peak_states.append(int(matcher.result.group('states')))
#                result.peak_bddnodes.append(int(matcher.result.group('bddnodes')))
            bdd_number = int(matcher.result.group('bddnodes'))
            if phase == 1:
                result.vp_peak_bdds.append(bdd_number)
            elif phase == 2:
                result.sp_peak_bdds.append(bdd_number)
            elif phase == 3:
                result.lp_peak_bdds.append(bdd_number)
                
        elif state == 2:
            if not matcher.match_reference_filename(line):
                continue
            result.reference_filename = matcher.result.group('file_name')
            state = 3
        elif state == 3:
            if not matcher.match_target_filename(line):
                continue
            result.target_filename = matcher.result.group('file_name')
            state = 4
        elif state == 4:
            if matcher.match_patch_result(line):
                result.is_validation_patch_required = 'yes'
                state = 20
            else:
                result.is_validation_patch_required = 'no'
                state = 5
        elif state == 5:
            if not matcher.match_patch_size(line):
                continue#raise Exception('Patch size cannot be read (line: ' + line + ')');
            result.validation_patch_states = matcher.result.group('states')
            result.validation_patch_bddnodes = matcher.result.group('bddnodes')
            state = 6
        elif state == 6:
            if matcher.match_patch_result(line):
                result.is_length_patch_required = 'yes'
                state = 21
            else:
                result.is_length_patch_required = 'no'
                state = 7
        elif state == 7:
            if not matcher.match_patch_size(line):
                continue#raise Exception('Patch size cannot be read (line: ' + line + ')');
            result.length_patch_states = matcher.result.group('states')
            result.length_patch_bddnodes = matcher.result.group('bddnodes')
            state = 8
        elif state == 8:
            if matcher.match_patch_result(line):
                result.is_sanitization_patch_required = 'yes'
                state = 22
            else:
                result.is_sanitization_patch_required = 'no'
                state = 9
        elif state == 9:
            if not matcher.match_patch_size(line):
                continue#raise Exception('Patch size cannot be read (line: ' + line + ')');
            result.sanitization_patch_states = matcher.result.group('states')
            result.sanitization_patch_bddnodes = matcher.result.group('bddnodes')
            state = 10
        elif state == 10:
            if not matcher.match_validation_patch_info(line):
                continue
            state = 11
        elif state == 11:
            if not matcher.match_time_info(line):
                state = 12
                continue
            result.validation_time_title.append( matcher.result.group('title') )
            result.validation_time.append( matcher.result.group('time') )
        elif state == 12:
            if not matcher.match_sanitization_patch_info(line):
                continue
            state = 13
        elif state == 13:
            if not matcher.match_time_info(line):
                state = 14
                continue
            result.sanitization_time_title.append( matcher.result.group('title') )
            result.sanitization_time.append( matcher.result.group('time') )
        elif state == 14:
            if not matcher.match_operations_info(line):
                continue
            state = 15
        elif state == 15:
            if not matcher.match_operations_details(line):
                state = 16
                continue
            result.operation_name.append( matcher.result.group('op_name') )
            result.operation_name.append( matcher.result.group('op_name') )
            result.operation_details.append( matcher.result.group('count') + ',' + matcher.result.group('time') )
        elif state == 16:        
            header.validation_time_title = result.validation_time_title
            header.sanitization_time_title = result.sanitization_time_title
            header.operation_name = result.operation_name
            outf.write(result.__str__())
            shared_results = result
            result = Result()
            state = 0
        elif state == 20:
            if not matcher.match_vp_filename(line):
                continue
            result.vp_filename = matcher.result.group('vp_auto_file')
            state = 5
        elif state == 21:
            if not matcher.match_lp_filename(line):
                continue
            result.lp_filename = matcher.result.group('lp_auto_file')
            state = 7
        elif state == 22:
            if not matcher.match_sp_filename(line):
                continue
            result.sp_filename = matcher.result.group('sp_auto_file')
            state = 23
        elif state == 23:
            if not matcher.match_refsink_filename(line):
                continue
            result.refsink_filename = matcher.result.group('refsink_auto_file')
            state = 9

#    outf.write(header.__str__())
    outf.close()
                 
def extract_peak_values(input_file, output_file=None):
    if not output_file:
        output_file = input_file + "_peak_values.csv"  
    outf = open(output_file, "w")
    with open(input_file, 'r') as f:
        matcher = Matcher()
        result = Result()
        state = 0
        for line in f:
            if state == 0:
                if not matcher.match_length_info(line):
                    continue          
                print "Handling " + line
                result.length_info = matcher.result.group('length')
                state = 1
            elif state == 1:
                if matcher.match_length_info_end(line):
                    state = 2
                    continue
                elif not matcher.match_peak_value(line):
                    continue
                bdd_number = int(matcher.result.group('bddnodes'))
                result.peak_bddnodes.append(bdd_number);
                    
            elif state == 2:       
                outf.write(result.get_peak_csv())
                result = Result()
                state = 0
    outf.close()

           