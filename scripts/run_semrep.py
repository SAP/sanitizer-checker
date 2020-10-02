#!/usr/bin/python

# -*- coding: utf-8 -*-
"""
Created on Thu Apr 10 00:51:20 2014

@author: abaki
"""

import patch_result_checker
import mincut_result_checker

from subprocess import Popen
from subprocess import PIPE
import os
import sys
import getopt
import shutil
import time


env_setup = {"LD_LIBRARY_PATH": "./libs"}
java_stack_size = "-Xss8m"
java_min_space = "-Xms128m"
java_max_space = "-Xmx16384M"

env_setup = {"LD_LIBRARY_PATH": "./libs"}

# Folders
output_folder = os.path.abspath(os.path.join(os.getcwd(), 'outputs') )
patch_automata_folder = os.path.abspath(os.path.join(output_folder, 'generated_patch_automata'))
patch_codes_folder = os.path.abspath(os.path.join(output_folder, 'generated_patch_codes'))

shutil.rmtree(output_folder)
os.makedirs(patch_automata_folder)
os.makedirs(patch_codes_folder)

def available_options():
    print "Available Options: "
    print "-h, --help                           : lists avaiable options"
    print "-r, --reference <filename>           : reference dependency graph file path"
    print "-t, --target <filename>              : target dependency graph file path"
    print "-f, --field-name <fieldname>         : field name to analyze"
    print "-l, --language <typename>            : output language for validation and length patch(PHP, JS)"

reference_filepath = ""
target_filepath = ""
field_name = ""
output_language = ""


try:
    opts, args = getopt.getopt(sys.argv[1:],"hr:t:f:l:",["reference=","target=", "field-name=", "language="])
except getopt.GetoptError:  
    available_options()
    sys.exit(2)

for opt, arg in opts:
    if opt == '-h':
        available_options()
        sys.exit()
    elif opt in ("-r", "--reference"):
        reference_filepath = arg
        default=False
    elif opt in ("-t", "--target"):
        target_filepath = arg
    elif opt in ("-f", "--field-name"):
        field_name = arg
    elif opt in ("-l", "--language"):
        output_language = arg

   

cmd = ""
cmd += "./SemRep "
cmd += "--reference " + reference_filepath + " "
cmd += "--target " + target_filepath + " "
cmd += "--fieldname " + field_name + " "

print "running cmd: " + cmd 

output = Popen(cmd, shell=True, env=env_setup, stdout=PIPE).communicate()[0]
print output

    
def get_file_path(unique=False):

    if not unique:
        return ""
    r_index = reference_filepath.rfind("/") + 1
    ref_file = reference_filepath[r_index:-4]    
    
    t_index = target_filepath.rfind("/") + 1
    tar_file = target_filepath[t_index:-4]

    return ref_file + "_" + tar_file + "_" + field_name + "_"    

def get_mincut_row_id():
    r_index = reference_filepath.rfind("/") + 1
    ref_file = reference_filepath[r_index:-4]        
    t_index = target_filepath.rfind("/") + 1
    tar_file = target_filepath[t_index:-4]
    return field_name + "_" + ref_file + "_" + tar_file

extension = "." + output_language.lower()
if extension == ".js":
    extension = ".html"
def write_simulation_code(code_output, output_file):
    start_index = 0
    end_index = 0
    extension = output_language.lower()
    if extension == "js":
        extension = "html"
    output_file += "." + extension
    if output_language.lower() == "php":
        start_index = code_output.find("<?php")
        end_index = code_output.rfind("?>") + 2
    elif output_language.lower() == "c":
        start_index = code_output.find("int stranger_match")
        end_index = code_output.rfind("}") + 1
    elif output_language.lower() == "js":
        start_index = code_output.find("<html>")
        end_index = code_output.rfind("</html>") + 7

    code = code_output[start_index:end_index]
    cf = open(output_file , "w")
    cf.write(code)
    cf.close()
    
    return code;
    
VP = "VLAB_VALIDATION_PATCH_BODY"
LP = "VLAB_LENGTH_PATCH_BODY"
SP = "VLAB_SANITIZATION_PATCH_BODY"
   
# default function names 
DVLPN = "stranger_match"
DSPN = "sanitize_input" 

def template_composition_code(language="js"):

    composition_code = ""
    language = language.lower()
    if language == "js":
        composition_code += "<!DOCTYPE html>\n"
        composition_code += "   <html>\n"
        composition_code += "   <head>\n"
        composition_code += "   <title>vlab@ucsb : www.cs.ucsb.edu/~vlab</title>"
        composition_code += "   <script>\n"
        composition_code += "       function vlab_validation_patch(str) {\n"
        composition_code += VP
        composition_code += "       }\n"
        composition_code += "       function vlab_length_validation_patch(str) {\n"
        composition_code += LP
        composition_code += "       }\n"        
        composition_code += "       function vlab_sanitization_patch(str) {\n"
        composition_code += SP
        composition_code += "       }\n"        
        composition_code += "       function vlabPatch() {\n"
        composition_code += "           var x=document.getElementById(\"fname\");\n"
        composition_code += "           var r=document.getElementById(\"result\");\n"
        composition_code += "           if (!vlab_validation_patch(x.value)) {\n"
        composition_code += "               if (!vlab_length_validation_patch(x.value)) {\n"
        composition_code += "                   r.style.color = \"rgb(0,255,0)\";\n"
        composition_code += "                   x.style.color = \"rgb(0,255,0)\";\n"
        composition_code += "                   r.innerHTML = \"&#10004; \" + vlab_sanitization_patch(x.value);\n"
        #composition_code += "                   x.value = vlab_sanitization_patch(x.value);\n"
        composition_code += "               }\n"
        composition_code += "               else {\n"
        composition_code += "                   r.style.color = \"rgb(255,0,0)\";\n"
        composition_code += "                   x.style.color = \"rgb(255,0,0)\";\n"
        composition_code += "                   r.innerHTML = \"&#10008; (length patch)\";\n"                 
        composition_code += "               }\n"
        composition_code += "           }\n"
        composition_code += "           else {\n"
        composition_code += "               r.style.color = \"rgb(255,0,0)\";\n"
        composition_code += "               x.style.color = \"rgb(255,0,0)\";\n"
        composition_code += "               r.innerHTML = \"&#10008; (validation patch)\";\n"                 
        composition_code += "           }\n"
        composition_code += "       }\n"
        composition_code += "       window.onload = vlabPatch;\n"
        composition_code += "   </script>\n"
        composition_code += "   </head>\n"
        composition_code += "   <body>\n"
        composition_code += "       Enter your string: <input type=\"text\" id=\"fname\" oninput=\"vlabPatch()\">&nbsp; <span id=\"result\" style=\"color:red\"></span>\n"
        composition_code += "       <p>As you type the characters, a function is triggered which validates and sanitizes the input string.</p>\n"
        composition_code += "       <p>(This composition should be applied before any other input validation and/or sanitization operation)</p>\n"
        composition_code += "   </body>\n"
        composition_code += "   </html>\n"
    else: #php
        composition_code = "<?php\n"
        composition_code += "   function vlab_validation_patch($str) {\n"
        composition_code += VP
        composition_code += "   }\n"
        composition_code += "   function vlab_length_validation_patch($str) {\n"
        composition_code += LP
        composition_code += "   }\n"        
        composition_code += "   function vlab_sanitization_patch($str) {\n"
        composition_code += SP
        composition_code += "   }\n"        
        composition_code += "   function vlabPatch($str) {\n"
        composition_code += "       if (!vlab_validation_patch($str)) {\n"
        composition_code += "           if (!vlab_length_validation_patch($str)) {\n"
        composition_code += "               echo \"validated and sanitized string: <b>\" . vlab_sanitization_patch($str) . \"</b>\";\n"
        composition_code += "           }\n"
        composition_code += "           else {\n"
        composition_code += "               echo \"not valid (length patch)\";\n"                
        composition_code += "           }\n"
        composition_code += "       }\n"
        composition_code += "       else {\n"
        composition_code += "           echo \"not valid (validation patch)\";\n"               
        composition_code += "       }\n"
        composition_code += "   }\n"
        composition_code += "   if (isset($_REQUEST['str'])) {\n"
        composition_code += "     vlabPatch($_REQUEST['str']);\n"
        composition_code += "   }\n"
        composition_code += "   else {\n"
        composition_code += "     echo \"Please send a POST or GET request with by using 'str' parameter!\";\n"               
        composition_code += "   }\n"
        composition_code += "?>\n"
        
    return composition_code
    
def replace_template_function_body(template, subject, replacement_code, function_name, default_body ):

    body = replacement_code[replacement_code.find("{", replacement_code.find(function_name)) + 1:]
    
    body = body[:body.find("}", body.find("return"))]
    
    return template.replace(subject,body)

template_ouput_code = template_composition_code(output_language)

fp_temp = get_file_path()

if fp_temp != "":    
    output_file_path = os.path.abspath(os.path.join(output_folder, fp_temp))    
    output_code_file_path = os.path.abspath(os.path.join(patch_codes_folder, fp_temp))
else:
    output_file_path = output_folder + "/"   
    output_code_file_path = patch_codes_folder + "/"
    

row_data_file = output_file_path + 'raw_result_row.csv'

patch_result_checker.extract_results(output, row_data_file)


vpr = patch_result_checker.shared_results.is_validation_patch_required
lpr = patch_result_checker.shared_results.is_length_patch_required
spr = patch_result_checker.shared_results.is_sanitization_patch_required

output = ""
print "....preparing automata outputs"
time.sleep(1)

if vpr == "yes":
    print "...Generating code for validation patch: " 
    cmd = ""
    cmd += "java " + java_stack_size + " " + java_min_space + " " + java_max_space + " "
    cmd += "-jar mincut_codegen.jar "
    cmd += "-p " + patch_result_checker.shared_results.vp_filename + " "
    cmd += "-s "
    cmd += "-l " + output_language + " "
    print "running command: " + cmd
    output = Popen(cmd, shell=True ,stdout=PIPE).communicate()[0]
    code_output_file = output_code_file_path + "validation_patch" + extension
    code_ouput = write_simulation_code(output, code_output_file)
    print "\nValidation Patch simulation code written: " + code_output_file + "\n"
    template_ouput_code = replace_template_function_body(template_ouput_code, VP, code_ouput, DVLPN, "      return false;\n")
else:
    print "...... no validation patch required"
    template_ouput_code = replace_template_function_body(template_ouput_code, VP, "", DVLPN, "      return false;\n")
    

if lpr == "yes":
    print "...Generating code for length patch: "
    cmd = ""    
    cmd += "java " + java_stack_size + " " + java_min_space + " " + java_max_space + " "
    cmd += "-jar mincut_codegen.jar "
    cmd += "-p " + patch_result_checker.shared_results.lp_filename + " "
    cmd += "-s "
    cmd += "-l " + output_language + " "
    print "running command: " + cmd
    output = Popen(cmd, shell=True ,stdout=PIPE).communicate()[0]
    code_output_file = output_code_file_path + "length_patch" + extension
    code_ouput = write_simulation_code(output, code_output_file)
    print "\nLength Patch simulation code written: " + code_output_file +"\n"
    
    template_ouput_code = replace_template_function_body(template_ouput_code, LP, code_ouput, DVLPN, "      return false;\n")
else:
    print "...... no length patch required"
    template_ouput_code = replace_template_function_body(template_ouput_code, LP, "", DVLPN, "      return false;\n")

default_body = "      return str;\n"
if output_language.lower() == "php" :
    default_body = "     return $str;\n"    
if spr == "yes":
    print "...Running mincut algorithm to make sanitization repair suggestions"
    cmd = ""
    cmd += "java " + java_stack_size + " " + java_min_space + " " + java_max_space + " "
    cmd += "-jar mincut_codegen.jar "
    cmd += "-p " + patch_result_checker.shared_results.sp_filename + " "
    cmd += "-r " + patch_result_checker.shared_results.refsink_filename + " "
    cmd += "-l " + output_language + " "
    print "running command: " + cmd
    output = Popen(cmd, shell=True ,stdout=PIPE).communicate()[0]
    code_output_file = output_code_file_path + "sanitization_patch" + extension
    code_ouput = write_simulation_code(output, code_output_file)
    print "\nSanitization Patch simulation code written: " + code_output_file
    template_ouput_code = replace_template_function_body(template_ouput_code, SP, code_ouput, DSPN, default_body)
    
    mincut_summary = output[:output.rfind("code:")]
    timers = output[output.find("~~~"):]
    mincut_summary += timers
    print mincut_summary
    mincut_result_file = output_file_path + "mincut_result_row.csv"
    
    mincut_result_checker.extract_results(mincut_summary, mincut_result_file, get_mincut_row_id())    
    
 
else:
    print "...... no sanitization patch required"
    template_ouput_code = replace_template_function_body(template_ouput_code, SP, "", DSPN, default_body)
 
if vpr == "yes" or lpr == "yes" or spr == "yes":
    composition_output_file = output_code_file_path + "final_patch" + extension
    cf = open(composition_output_file, "w")
    cf.write(template_ouput_code)
    cf.close()

print "\n\n*************************************************************************************************"
print "-------------------------------------------------------------------------------------------------"    
print "------------------------------------------ EXECUTION SUMMARY ------------------------------------"
print "-------------------------------------------------------------------------------------------------" 
print "*************************************************************************************************\n"
print "--->  validation patch: " + vpr + ", length patch: " + lpr + ", sanitization patch: " + spr
print "\n--->  you can check the outputs folder for the generated output files and generated codes for patches: " + output_folder  
print "\n\n"

