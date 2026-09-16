#-*- coding: utf-8 -*-
# "This Project Using Pytnon2 "
from __future__ import division
from tools.modified.androguard.core.bytecodes import apk
from tools.modified.androguard.core.bytecodes import dvm
from tools.modified.androguard.core.analysis import analysis
from tools.modified.androguard.core import bytecode
from tools.modified.androguard import misc
import uuid
import os
import re
import json
import time
from datetime import datetime
import hashlib  # sha256 hash
from textwrap import TextWrapper  # for indent in output
import base64
import collections  # for sorting key of dictionary
import traceback
import random
import argparse
from zipfile import BadZipfile
from ConfigParser import SafeConfigParser
import platform
import imp
import sys
import requests
reload(sys)
sys.setdefaultencoding('utf-8')
DYLANPACKAGENAME = None
inserted_app_id = ''
"""
	*****************************************************************************
	** AndroBugs Framework - Android App Security Vulnerability Scanner        **
	** This tool is created by Yu-Cheng Lin (a.k.a. AndroBugs) @ AndroBugs.com **
	** Twitter: @AndroBugs                                                     **
	** Email: androbugs.framework@gmail.com                                    **
	*****************************************************************************

	** Read Python codeing style first: http://www.python.org/dev/peps/pep-0008/ **

	1.This script run under Python 2.7. DO NOT use Python 3.x

	2.You need to install 'chilkat' component version in accordance with Python 2.7 first. This is for certificate checking.
	  See the explanation of function 'def get_certificate(self, filename)' in 'apk.py' file
	  => It becomes optional now. Since the related code is not comment out for ease of use and install.

	3.Use command 'grep -nFr "#Added by AndroBugs" *' to see what AndroBugs Framework has added to Androguard Open Source project under "tools/modified/androguard" root directory.

	4.Notice the "encoding" when copy and paste into this file (For example: the difference between single quote ' ).

	5.** Notice: In AndroidManifest.xml => The value "TRUE" or "True" or "true" are all the same (e.g. [android:exported="TRUE"] equals to [android:exported="true"]). 
	  So if you want to check whether it is true, you should MAKE IT LOWER first. Otherwise, your code may have security issues. **

	Read these docs first:
		1.https://source.android.com/devices/tech/dalvik/dex-format
		2.http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html

	Provide the user the options:
		1.Specify the excluded package name (ex: Facebook.com, Parse.com) and put it into "STR_REGEXP_TYPE_EXCLUDE_CLASSES"
		2.Show the "HTTP Connection" related code or not
		3.Show the "KeyStore" related code or not

	Flag:
		[Critical] => very critical
		[Warning]  => it's ok and not really need to change
		[Notice]   => For hackers, you should notice.
		[Info]	   => Information

	You can use these functions provided by the FilteringEngine to exclude class packages:
		(1)Filter single class name:
			is_class_name_not_in_exclusion(single_class_name_string)

		(2)Filter a list of class name:
			filter_list_of_classes(class_name_list)

		(3)Filter a list of method name:
			filter_list_of_methods(method_list)

		(4)Filter a list of Path:
			filter_list_of_paths(d, path_list)  #a list of PathP

		(5)Filter a list of Variables: #variables_list example: None or [[('R', 166), 5058]] or [[('R', 8), 5050], [('R', 24), 5046]]
			filter_list_of_variables(d, variables_list)   

		(6)Filter dictionary key classes: (filter the class names in the key)
			(boolean) is_all_of_key_class_in_dict_not_in_exclusion(key)

		(7) ...

	Current self-defined error id:
		 - fail_to_unzip_apk_file
		 - apk_file_name_slash_twodots_error
		 - apk_file_not_exist
		 - package_name_empty
		 - classes_dex_not_in_apk

		 search the corresponding error by using MongoDB criteria " {"analyze_error_id":"[error_id]"} "

	AndroBugs Framework is supported with MongoDB. Add "-s" argument if you want all the analysis results to be stored into the MongoDB.
	Please check the "maldroid-db.cfg" file for database configuration.
"""

# Fix settings:

TYPE_REPORT_OUTPUT_ONLY_PRINT = "print"
TYPE_REPORT_OUTPUT_ONLY_FILE = "file"
TYPE_REPORT_OUTPUT_PRINT_AND_FILE = "print_and_file"

TYPE_COMPARE_ALL = 1
TYPE_COMPARE_ANY = 2

ANALYZE_MODE_SINGLE = "single"
ANALYZE_MODE_MASSIVE = "massive"

# AndroidManifest permission protectionLevel constants
PROTECTION_NORMAL = 0  # "normal" or not set
PROTECTION_DANGEROUS = 1
PROTECTION_SIGNATURE = 2
PROTECTION_SIGNATURE_OR_SYSTEM = 3
PROTECTION_MASK_BASE = 15
PROTECTION_FLAG_SYSTEM = 16
PROTECTION_FLAG_DEVELOPMENT = 32
PROTECTION_MASK_FLAGS = 240

LEVEL_CRITICAL = "Critical"
LEVEL_WARNING = "Warning"
LEVEL_NOTICE = "Notice"
LEVEL_INFO = "Info"

LINE_MAX_OUTPUT_CHARACTERS_WINDOWS = 160  # 100
LINE_MAX_OUTPUT_CHARACTERS_LINUX = 160
LINE_MAX_OUTPUT_INDENT = 20
#-----------------------------------------------------------------------------------------------------

# Customized settings:

DEBUG = True
ANALYZE_ENGINE_BUILD_DEFAULT = 1  # Analyze Engine(use only number)

DIRECTORY_APK_FILES = ""  # "APKs/"

# when compiling to Windows executable, switch to "TYPE_REPORT_OUTPUT_ONLY_FILE"
REPORT_OUTPUT = TYPE_REPORT_OUTPUT_PRINT_AND_FILE
# Only need to specify when (REPORT_OUTPUT = TYPE_REPORT_OUTPUT_ONLY_FILE) or (REPORT_OUTPUT = TYPE_REPORT_OUTPUT_PRINT_AND_FILE)
DIRECTORY_REPORT_OUTPUT = "Reports/"
# DIRECTORY_REPORT_OUTPUT = "Massive_Reports/"

#-----------------------------------------------------------------------------------------------------
"""
Package for exclusion:
Lcom/google/
Lcom/aviary/android/
Lcom/parse/
Lcom/facebook/
Lcom/tapjoy/
Lcom/android/
"""

# The exclusion list settings will be loaded into FilteringEngine later
STR_REGEXP_TYPE_EXCLUDE_CLASSES = "^(Landroid/support/|Lcom/actionbarsherlock/|Lorg/apache/|Lcom/facebook/)"
ENABLE_EXCLUDE_CLASSES = True

#-----------------------------------------------------------------------------------------------------
# Excluded Labs: Detections that are outdated or prone to false positives
# Add lab ID to skip the detection; remove to re-enable
# Format: "lab_xxx" => reason for exclusion

EXCLUDED_LABS = {
    # --- Outdated (vulnerability already fixed in modern Android) ---
    #"lab_016",   # Master Key Type I (CVE-2013-4787) - fixed in Android 4.4, 2013 "Updated ! "
    #"lab_035",   # HttpURLConnection pre-Froyo bug - Android 2.2 (API 8), 2010 : Updated ! -> SSL Ping Check ! 
    #"lab_036",   # beginTransactionNonExclusive API<11 - Android 3.0, 2011  -> 
    #"lab_044",   # Fragment injection (CVE-2013-6271) - fixed in Android 4.4, 2013 --> updated Dirty Stream Vulnerability 
    #"lab_052",   # SQLite Journal (CVE-2011-3901) - fixed in Android 4.0, 2011
    #"lab_062",   # System sharedUserId + Master Key - depends on lab_016
    "lab_023",
    # --- Deprecated API (detection target no longer used) ---
    #"lab_018",   # ACCESS_MOCK_LOCATION - removed in Android 6.0 (API 23) Updated -> Improper FileProvider Configuration
    "lab_030",   # ALLOW_ALL_HOSTNAME_VERIFIER - org.apache.http deprecated in API 22
    "lab_032",   # HttpHost default scheme - org.apache.http deprecated in API 22
    # --- False positive prone ---
    "lab_002",   # Security Methods - regex "config|setting" too broad
    "lab_003",   # Security Classes - regex "config|setting" too broad
    "lab_043",   # External Storage - Android 10+ Scoped Storage
    # --- Superseded (functionality fully covered by another lab) ---
    "lab_066",   # Adb Backup check - 功能已被 lab_073 (4.1.2.3.14 備份資料敏感性資料保護) 完整涵蓋
}

#-----------------------------------------------------------------------------------------------------
# For output the static result

report_dict_zhtw = collections.OrderedDict()
report_dict_en = collections.OrderedDict()
output_pdf_url = " http://140.114.77.172:15148/api/report"

#-----------------------------------------------------------------------------------------------------




#--------

class Writer:
    def __init__(self, excluded_labs=None):
        self.__package_information = {}
        self.__cache_output_detail_stream = []
        # Store the result information (key: tag ; value: information_for_each_vector)
        self.__output_dict_vector_result_information = {}
        self.__output_current_tag = ""  # The current vector analyzed

        ## New Code For Lab Write Counter
        self.__lab_write_counters = {}
        self.__max_write_per_lab = 10

        # Analyze vector result (for more convenient to save in disk)
        self.__file_io_result_output_list = []
        # Analyze header result (include package_name, md5, sha1, etc.)
        self.__file_io_information_output_list = []
        self.bIsValidThisRound = False

        # Excluded labs list - detections in this set will be skipped
        self.__excluded_labs = excluded_labs if excluded_labs else set()

    def simplifyClassPath(self, class_name):
        if class_name.startswith('L') and class_name.endswith(';'):
            return class_name[1:-1]
        return class_name

    def show_Path(self, vm, path, indention_space_count=0):
        """
                Different from analysis.show_Path, this "show_Path" writes to the tmp writer 
        """

        cm = vm.get_class_manager()

        if isinstance(path, analysis.PathVar):
            dst_class_name, dst_method_name, dst_descriptor = path.get_dst(cm)
            info_var = path.get_var_info()

            self.write("=> %s (0x%x) ---> %s->%s%s" %
                       (info_var, path.get_idx(), dst_class_name,
                        dst_method_name, dst_descriptor),
                       indention_space_count)

        else:
            if path.get_access_flag() == analysis.TAINTED_PACKAGE_CALL:
                src_class_name, src_method_name, src_descriptor = path.get_src(
                    cm)
                dst_class_name, dst_method_name, dst_descriptor = path.get_dst(
                    cm)

                self.write("=> %s->%s%s (0x%x) ---> %s->%s%s" %
                           (src_class_name, src_method_name, src_descriptor,
                            path.get_idx(), dst_class_name, dst_method_name,
                            dst_descriptor), indention_space_count)

            else:
                src_class_name, src_method_name, src_descriptor = path.get_src(
                    cm)

                self.write("=> %s->%s%s (0x%x)" %
                           (src_class_name, src_method_name, src_descriptor,
                            path.get_idx()), indention_space_count)

    def show_Path_only_source(self, vm, path, indention_space_count=0):
        cm = vm.get_class_manager()
        src_class_name, src_method_name, src_descriptor = path.get_src(cm)
        self.write("=> %s->%s%s" % (src_class_name, src_method_name,
                                    src_descriptor), indention_space_count)

    def show_Paths(self, vm, paths, indention_space_count=0):
        """
                Show paths of packages
                :param paths: a list of :class:`PathP` objects

                Different from "analysis.show_Paths", this "show_Paths" writes to the tmp writer 
        """
        for path in paths:
            self.show_Path(vm, path, indention_space_count)

    def show_single_PathVariable(self, vm, path, indention_space_count=0):
        """
                Different from "analysis.show_single_PathVariable", this "show_single_PathVariable" writes to the tmp writer 

                method[0] : class name
                method[1] : function name
                method[2][0] + method[2][1]) : description
        """
        access, idx = path[0]
        m_idx = path[1]
        method = vm.get_cm_method(m_idx)

        self.write("=> %s->%s %s" % (method[0], method[1],
                                     method[2][0] + method[2][1]),
                   indention_space_count)

    # Output: stoping

    def startWriter(self,
                    tag,
                    level,
                    summary,
                    title_msg,
                    special_tag=None,
                    cve_number=""):
        """
                "tag" is for internal usage
                "level, summary, title_msg, special_tag, cve_number" will be shown to the users
                It will be sorted by the "tag". The result will be sorted by the "tag".

                Notice: the type of "special_tag" is "list"
        """
        self.bIsValidThisRound = self.IsValid(summary)
        if(self.bIsValidThisRound == False):
            return
        #writeInf("",)
        #print("Origin : " + summary)
        """
            Now, we want the whole title, and more !
        """
        # summary = self.StripContect(summary)
        #print("Strip : " + summary)
        self.completeWriter()
        self.__output_current_tag = tag

        assert (
            (tag is not None) and (level is not None) and (summary is not None)
            and (title_msg is not None)
        ), "\"tag\", \"level\", \"summary\", \"title_msg\" should all have it's value."

        if tag not in self.__output_dict_vector_result_information:
            self.__output_dict_vector_result_information[tag] = []

        dict_tmp_information = dict()
        dict_tmp_information["level"] = level
        dict_tmp_information["title"] = title_msg.rstrip('\n')
        dict_tmp_information["summary"] = summary.rstrip('\n')
        dict_tmp_information["count"] = 0
        if special_tag:
            assert isinstance(
                special_tag,
                list), "Tag [" + tag + "] : special_tag should be list"
            # Notice: the type of "special_tag" is "list"
            dict_tmp_information["special_tag"] = special_tag
        if cve_number:
            assert isinstance(
                cve_number,
                basestring), "Tag [" + tag + "] : special_tag should be string"
            dict_tmp_information["cve_number"] = cve_number

        self.__output_dict_vector_result_information[tag] = dict_tmp_information

    def IsValid(self, _Content):
        # Check if the lab is in the excluded list
        if self.__excluded_labs:
            p = re.compile(r'\[(lab_\d+)\]')
            match = p.search(_Content)
            if match:
                lab_id = match.group(1)
                if lab_id in self.__excluded_labs:
                    print("[SKIP] {} - excluded by EXCLUDED_LABS".format(lab_id))
                    return False
        return True
    def StripContect(self,_Content):
        """
            [Ben]
            Modify the summary by extracting the [工-x.x.x.x]
        """
        iIndex = _Content.find('工')
        iEndIndex = _Content.find(']',iIndex)
        _Content = _Content[iIndex-1:iEndIndex+1]
        return _Content
    def get_valid_encoding_utf8_string(self, utf8_string):
        """
                unicode-escape: http://stackoverflow.com/questions/4004431/text-with-unicode-escape-sequences-to-unicode-in-python
                Encoding and Decoding:
                        http://blog.wahahajk.com/2009/08/unicodedecodeerror-ascii-codec-cant.html
                        http://www.evanjones.ca/python-utf8.html
                        http://www.jb51.net/article/26543.htm
                        http://www.jb51.net/article/17560.htm
        """
        return utf8_string.decode('unicode-escape').encode('utf8')

    def write(self, detail_msg, indention_space_count=0):
        if(self.bIsValidThisRound == True):
            current_lab = self.__output_current_tag

            #init the lab write counter
            if current_lab not in self.__lab_write_counters:
                self.__lab_write_counters[current_lab] = 0
            #check the lab write counter
            if self.__lab_write_counters[current_lab] < self.__max_write_per_lab:
                self.__cache_output_detail_stream.append(detail_msg + "\n")
                self.__lab_write_counters[current_lab] += 1
            elif self.__lab_write_counters[current_lab] == self.__max_write_per_lab:
                self.__cache_output_detail_stream.append("... \n")    
                self.__lab_write_counters[current_lab] += 1
            
    def get_packed_analyzed_results_for_mongodb(self):
        # For external storage

        analyze_packed_result = self.getInf()

        if analyze_packed_result:
            if self.get_analyze_status() == "success":
                analyze_packed_result[
                    "details"] = self.__output_dict_vector_result_information
            return analyze_packed_result

        return None

    def get_search_enhanced_packed_analyzed_results_for_mongodb(self):
        # For external storage

        analyze_packed_result = self.getInf()

        if analyze_packed_result:
            if self.get_analyze_status() == "success":

                prepared_search_enhanced_result = []

                for tag, dict_information in self.__output_dict_vector_result_information.items(
                ):

                    search_enhanced_result = dict()

                    search_enhanced_result["vector"] = tag
                    search_enhanced_result["level"] = dict_information["level"]
                    search_enhanced_result[
                        "analyze_engine_build"] = analyze_packed_result[
                            "analyze_engine_build"]
                    search_enhanced_result[
                        "analyze_mode"] = analyze_packed_result["analyze_mode"]
                    if "analyze_tag" in analyze_packed_result:
                        search_enhanced_result[
                            "analyze_tag"] = analyze_packed_result[
                                "analyze_tag"]
                    search_enhanced_result[
                        "package_name"] = analyze_packed_result["package_name"]
                    if "package_version_code" in analyze_packed_result:
                        search_enhanced_result[
                            "package_version_code"] = analyze_packed_result[
                                "package_version_code"]
                    search_enhanced_result[
                        "file_sha512"] = analyze_packed_result["file_sha512"]
                    search_enhanced_result[
                        "signature_unique_analyze"] = analyze_packed_result[
                            "signature_unique_analyze"]

                    prepared_search_enhanced_result.append(
                        search_enhanced_result)

                return prepared_search_enhanced_result

        return None

    def getInf(self, key=None, default_value=None):
        if key is None:
            return self.__package_information

        if key in self.__package_information:
            value = self.__package_information[key]
            # [Important] if default_value="", the result of the condition is "False"
            if (value is None) and (default_value is not None):
                return default_value
            return value

        #not found
        # [Important] if default_value="", the result of the condition is "False"
        if default_value:
            return default_value

        return None
    def MyPrint(self):
        print("Hellooooobbbbbbbbbbbbbbbb")
        return
    def writePlainInf(self, msg):
        # if DEBUG :
        print(str(msg))
        # [Recorded here]
        self.__file_io_information_output_list.append(str(msg))

    def writeInf(self,
                 key,
                 value,
                 extra_title,
                 extra_print_original_title=False):
        # if DEBUG :
        if extra_print_original_title:
            print(str(extra_title))
            # [Recorded here]
            self.__file_io_information_output_list.append(str(extra_title))
        else:
            print(extra_title + ": " + str(value))
            # [Recorded here]
            self.__file_io_information_output_list.append(
                extra_title + ": " + str(value))

        self.__package_information[key] = value

    def writeInf_ForceNoPrint(self, key, value):
        self.__package_information[key] = value

    def update_analyze_status(self, status):
        self.writeInf_ForceNoPrint("analyze_status", status)

    def get_analyze_status(self):
        return self.getInf("analyze_status")

    def get_total_vector_count(self):
        if self.__output_dict_vector_result_information:
            return len(self.__output_dict_vector_result_information)
        return 0

    def completeWriter(self):
        # save to DB
        if (self.__cache_output_detail_stream) and (self.__output_current_tag
                                                    != ""):
            # This is the preferred way if you know that your variable is a string. If your variable could also be some other type then you should use myString == ""

            current_tag = self.__output_current_tag
            # try :
            if current_tag in self.__output_dict_vector_result_information:
                self.__output_dict_vector_result_information[current_tag][
                    "count"] = len(self.__cache_output_detail_stream)
                """
					Use xxx.encode('string_escape') to avoid translating user code into command
					For example: regex in the code of users' applications may include "\n" but you should escape it.

					I add "str(xxx)" because the "xxx" of xxx.encode should be string but "line" is not string.
					Now the title and detail of the vectors are escaped(\n,...), so you need to use "get_valid_encoding_utf8_string"

					[String Escape Example] 
					http://stackoverflow.com/questions/6867588/how-to-convert-escaped-characters-in-python
					>>> escaped_str = 'One \\\'example\\\''
					>>> print escaped_str.encode('string_escape')
					One \\\'example\\\'
					>>> print escaped_str.decode('string_escape')
					One 'example'
				"""

                output_string = ""
                for line in self.__cache_output_detail_stream:
                    if isinstance(line, unicode):
                        output_string = output_string + \
                            line.encode("utf8").encode('string_escape')
                    else:
                        # here
                        # unicode form \xe5\x8e\x9f\xe5\xa7\x8b\xe7\xb7\xa8\xe mix with asci SU5WQUxJRA
                        # To escape the "\n" shown in the original string inside the APK
                        output_string = output_string + line

                self.__output_dict_vector_result_information[current_tag][
                    "vector_details"] = output_string.rstrip(
                        str("\n").encode('string_escape'))

        self.__output_current_tag = ""
        # Clear the items in the list
        self.__cache_output_detail_stream[:] = []

    def is_dict_information_has_cve_number(self, dict_information):
        if dict_information:
            if "cve_number" in dict_information:
                return True
        return False

    def is_dict_information_has_special_tag(self, dict_information):
        if dict_information:
            if "special_tag" in dict_information:
                if dict_information["special_tag"]:
                    return True
        return False

    def __sort_by_level(key, value):
        try:
            level = value[1]["level"]

            if level == LEVEL_CRITICAL:
                return 5
            elif level == LEVEL_WARNING:
                return 4
            elif level == LEVEL_NOTICE:
                return 3
            elif level == LEVEL_INFO:
                return 2
            else:
                return 1
        except KeyError:
            return 1

    def append_to_file_io_information_output_list(self, line):
        # Only write to the header of the "external" file
        self.__file_io_information_output_list.append(line)

    def save_result_to_file(self, output_file_path, args):

        print("* Savefile txt")
        if not self.__file_io_result_output_list:
            self.load_to_output_list(args)

        try:
            import codecs
            print(output_file_path)
            with codecs.open(output_file_path, "w", "utf8") as f:
                if self.__file_io_information_output_list:
                    for line in self.__file_io_information_output_list:
                        f.write(line + "\n")
                for line in self.__file_io_result_output_list:
                    f.write(line + "\n")

            print("<<< Analysis report is generated: " +
                  os.path.abspath(output_file_path) + " >>>")
            print("")

            return True
        except IOError as err:
            if DEBUG:
                print("[Error on writing output file to disk]")
            return False

    def show(self, args):
        if not self.__file_io_result_output_list:
            self.load_to_output_list(args)

        if self.__file_io_result_output_list:
            for line in self.__file_io_result_output_list:
                print(line)

    def output(self, line):
        # Store here for later use on "print()" or "with ... open ..."
        # [Recorded here]
        self.__file_io_result_output_list.append(line)

    # Store here for later use on "print()" or "with ... open ..."
    def output_and_force_print_console(self, line):
        # [Recorded here]
        self.__file_io_result_output_list.append(line)
        print(line)

    def load_to_output_list(self, args):
        """
                tag => dict(level, title_msg, special_tag, cve_number)
                tag => list(detail output)

                print(self.__output_dict_vector_result_information)
                print(self.__output_dict_vector_result_information["vector_details"])

                Example output:
                        {'WEBVIEW_RCE': {'special_tag': ['WebView', 'Remote Code Execution'], 'title': "...", 'cve_number': 'CVE-2013-4710', 'level': 'critical'}}
                        "Lcom/android/mail/ui/ConversationViewFragment;->onCreateView(Landroid/view/LayoutInflater; Landroid/view/ViewGroup; 
                                Landroid/os/Bundle;)Landroid/view/View; (0xa4) ---> Lcom/android/mail/browse/ConversationWebView;->addJavascriptInterface(Ljava/lang/Object; Ljava/lang/String;)V"

                "vector_details" is a detail string of a vector separated by "\n" controlled by the users

        """

        self.__file_io_result_output_list[:] = []  # clear the list

        wrapperTitle = TextWrapper(
            initial_indent=' ' * 11,
            subsequent_indent=' ' * 11,
            width=args.line_max_output_characters)
        wrapperDetail = TextWrapper(
            initial_indent=' ' * 15,
            subsequent_indent=' ' * 20,
            width=args.line_max_output_characters)

        sorted_output_dict_result_information = collections.OrderedDict(
            sorted(self.__output_dict_vector_result_information.items())
        )  # Sort the dictionary by key

        # Output the sorted dictionary by level
        for tag, dict_information in sorted(
                sorted_output_dict_result_information.items(),
                key=self.__sort_by_level,
                reverse=True):
            extra_field = ""
            if self.is_dict_information_has_special_tag(dict_information):
                for i in dict_information["special_tag"]:
                    extra_field += ("<" + i + ">")
            if self.is_dict_information_has_cve_number(dict_information):
                extra_field += ("<#" + dict_information["cve_number"] + "#>")

            if args.show_vector_id:
                self.output("[%s] %s %s (Vector ID: %s):" %
                            (dict_information["level"], extra_field,
                             dict_information["summary"], tag))
            else:
                self.output("[%s] %s %s:" %
                            (dict_information["level"], extra_field,
                             dict_information["summary"]))

            for line in dict_information["title"].split('\n'):
                self.output(wrapperTitle.fill(line))

            if "vector_details" in dict_information:
                for line in dict_information["vector_details"].split('\n'):
                    self.output(wrapperDetail.fill(line))

        self.output(
            "------------------------------------------------------------")

        stopwatch_total_elapsed_time = self.getInf("time_total")
        stopwatch_analyze_time = self.getInf("time_analyze")
        if stopwatch_total_elapsed_time and stopwatch_analyze_time:

            if (REPORT_OUTPUT == TYPE_REPORT_OUTPUT_ONLY_FILE):
                self.output_and_force_print_console(
                    "Maldroid analyzing time: " + str(stopwatch_analyze_time) +
                    " secs")
                self.output_and_force_print_console(
                    "Total elapsed time: " +
                    str(stopwatch_total_elapsed_time) + " secs")
            else:
                self.output("Maldroid analyzing time: " +
                            str(stopwatch_analyze_time) + " secs")
                self.output("Total elapsed time: " +
                            str(stopwatch_total_elapsed_time) + " secs")

        if args.store_analysis_result_in_db:

            analysis_tips_output = "("

            if args.analyze_engine_build:
                analysis_tips_output += "analyze_engine_build: " + \
                    str(args.analyze_engine_build) + ", "

            if args.analyze_tag:
                analysis_tips_output += "analyze_tag: " + \
                    str(args.analyze_tag) + ", "

            if analysis_tips_output.endswith(", "):
                analysis_tips_output = analysis_tips_output[:-2]

            analysis_tips_output += ")"

            if (REPORT_OUTPUT == TYPE_REPORT_OUTPUT_ONLY_FILE):
                self.output_and_force_print_console(
                    "<<< Analysis result has stored into database " +
                    analysis_tips_output + " >>>")
            else:
                self.output("<<< Analysis result has stored into database " +
                            analysis_tips_output + " >>>")

    # TODO: for pdf json format
    def get_json(self):
        dict_to_json = self.__output_dict_vector_result_information
        
        # zh_tw: json
        report_dict_zhtw["mast_report"] = collections.OrderedDict()
        # android_static_json_zhtw = open('/home/py/android_static_zhtw.json', 'r')
        
        # path detection for JSON files (resolve relative to this script's dir)
        _maldroid_dir = os.path.dirname(os.path.abspath(__file__))
        android_static_json_zhtw = open(os.path.join(_maldroid_dir, 'android_static_zhtw.json'), 'r')
        
        android_static_dict_zhtw = json.load(android_static_json_zhtw, object_pairs_hook=collections.OrderedDict)
        # en: json
        report_dict_en["mast_report"] = collections.OrderedDict()
        #android_static_json_en = open('/home/py/android_static_en.json', 'r')
        
        # path detection for JSON files (resolve relative to this script's dir)
        android_static_json_en = open(os.path.join(_maldroid_dir, 'android_static_en.json'), 'r')
        android_static_dict_en = json.load(android_static_json_en, object_pairs_hook=collections.OrderedDict)
        
        # Import lab_num
        for key, value in android_static_dict_zhtw.items():
            report_dict_zhtw["mast_report"][key] = {
                "isDetected": False,
                "type": ""
            }
            report_dict_en["mast_report"][key] = {
                "isDetected": False,
                "type": ""
            }
        # Detectiong rule
        for k,v in dict_to_json.items():
            # extract the [lab_001]
            p1 = re.compile(r'[\[](.*?)[\]]', re.S) 
            lab_tag_list = re.findall(p1, v["summary"])

            # ex: Get [lab_001]
            if lab_tag_list[0] in android_static_dict_zhtw:
                lab_tag = lab_tag_list[0]
                # lab_tag hasn't content

                if report_dict_zhtw["mast_report"][lab_tag]["isDetected"] == False:
                    report_dict_zhtw["mast_report"][lab_tag]["data"] = []
                    report_dict_en["mast_report"][lab_tag]["data"] = []
                    # zhtw
                    # report_dict_zhtw["mast_report"][lab_tag]["data"] = [
                    #     {
                    #         "description": v["title"].split("||")[1],
                    #         "details": v["vector_details"] if "vector_details" in v else ''
                    #     }
                    # ]
                    if "vector_details" in v:
                        for dataitem in v["vector_details"].split('=>'):
                            report_dict_zhtw["mast_report"][lab_tag]["data"].append(
                                {
                                    "description": v["title"].split("||")[0],
                                    "details": dataitem
                                }
                                )
                    else:
                        report_dict_zhtw["mast_report"][lab_tag]["data"].append(
                            {
                                "description": v["title"].split("||")[0],
                                "details": ''
                            }
                        )
                    report_dict_zhtw["mast_report"][lab_tag]["isDetected"] = True
                    report_dict_zhtw["mast_report"][lab_tag]["type"] = v["special_tag"] if "special_tag" in v else []
                    # en
                    print(v["title"])
                    # report_dict_en["mast_report"][lab_tag]["data"] = [
                    #     {
                    #         "description": v["title"].split("||")[1],
                    #         "details": v["vector_details"] if "vector_details" in v else ''
                    #     }
                    # ]
                    if "vector_details" in v:
                        for dataitem in v["vector_details"].split('=>'):
                            report_dict_en["mast_report"][lab_tag]["data"].append(
                                {
                                    "description": v["title"].split("||")[1],
                                    "details": dataitem
                                }
                                )
                    else:
                        report_dict_en["mast_report"][lab_tag]["data"].append(
                            {
                                "description": v["title"].split("||")[1],
                                "details": ''
                            }
                        )
                    report_dict_en["mast_report"][lab_tag]["isDetected"] = True
                    report_dict_en["mast_report"][lab_tag]["type"] = v["special_tag"] if "special_tag" in v else []
                # lab_tag has other contents, append other description
                    
                else:
                    # zhtw
                    report_dict_zhtw["mast_report"][lab_tag]["data"].append(
                        {
                            "description": v["title"].split("||")[0],
                            "details": v["vector_details"] if "vector_details" in v else '',
                        }
                    )
                    # en
                    report_dict_en["mast_report"][lab_tag]["data"].append(
                        {
                            "description": v["title"].split("||")[1],
                            "details": v["vector_details"] if "vector_details" in v else '',
                        }
                    )
        for k,v in report_dict_zhtw["mast_report"].items():
            if v["isDetected"] == True:
                android_static_dict_zhtw[k]["desc"] = v["data"][0]["description"]
        for k,v in report_dict_en["mast_report"].items():
            if v["isDetected"] == True:
                android_static_dict_en[k]["desc"] = v["data"][0]["description"]

        # Ensure required fields exist with default values
        required_fields = {
            "md5": "unknown",
            "sha256": "unknown",
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "file_name": "unknown",
            "app_name": "unknown",
            "app_version": "unknown",
            "package_version_code": "0",
            "min_sdk": "0",
            "target_sdk": "0",
            "url_list": []
        }

        for key, default_value in required_fields.items():
            if key not in report_dict_zhtw:
                report_dict_zhtw[key] = default_value
            if key not in report_dict_en:
                report_dict_en[key] = default_value

        merge_dict_tw = {}
        merge_dict_tw["lang"] = "zh-TW"
        merge_dict_tw["system"] = "android"
        merge_dict_tw["rule"] = android_static_dict_zhtw
        merge_dict_tw["result"] = report_dict_zhtw


        merge_dict_en = {}
        merge_dict_en["lang"] = "en"
        merge_dict_en["system"] = "android"
        merge_dict_en["rule"] = android_static_dict_en
        merge_dict_en["result"] = report_dict_en
        # https://www.cnblogs.com/jay54520/p/8717166.html
        #analysis_result_json_zhtw = json.dumps(report_dict_zhtw, indent=4, ensure_ascii=False)
        #analysis_result_json_en = json.dumps(report_dict_en, indent=4, ensure_ascii=False)
        return  merge_dict_tw, merge_dict_en

    def generate_pdf(self, args, merge_dict_tw, merge_dict_en):

        import requests as req
        global output_pdf_url
        from collections import OrderedDict
        try:
            # Resolve output dir relative to the Frida directory (not the CWD,
            # which is '/' when launched by webapp.py) so webapp.py can find it.
            _frida_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            result_dir = os.path.join(_frida_dir, 'static_analysis_result')
            if not os.path.exists(result_dir):
                os.makedirs(result_dir)

            # Get package name from APK
            package_name = "unknown_app"  # Default fallback
            try:
                # Prefer the package name resolved during analysis (global), then
                # self.a, so the report filename matches webapp's {packageName}.json
                if 'DYLANPACKAGENAME' in globals() and DYLANPACKAGENAME and DYLANPACKAGENAME.strip():
                    package_name = DYLANPACKAGENAME
                elif hasattr(self, 'a') and self.a:
                    pkg = self.a.get_package()
                    # Check if package name is not empty
                    if pkg and pkg.strip():
                        package_name = pkg
            except:
                pass

            # Select data based on language parameter
            lang = args.lang if hasattr(args, 'lang') else 'en'

            # Normalize language code (zh -> zh-TW)
            if lang == 'zh':
                lang = 'zh-TW'

            if lang == 'zh-TW':
                data_to_use = merge_dict_tw
                lang_suffix = "_zh"
                print("[INFO] Using Traditional Chinese (zh-TW) report")
            else:
                data_to_use = merge_dict_en
                lang_suffix = "_en"
                print("[INFO] Using English (en) report")

            # Use codecs for Python 2.7 compatibility (open() doesn't support encoding parameter)
            import codecs

            # Create JSON file with package name and language suffix (for reference)
            json_filename_lang = os.path.join(result_dir, "{}{}.json".format(package_name, lang_suffix))
            with open(json_filename_lang, 'w') as outfile:
                json.dump(data_to_use, outfile)
            print("Created JSON report: {}".format(json_filename_lang))

            # IMPORTANT: Also create JSON without language suffix for webapp.py compatibility
            # webapp.py expects: {packageName}.json (without _en or _zh suffix)
            json_filename_webapp = os.path.join(result_dir, "{}.json".format(package_name))
            with open(json_filename_webapp, 'w') as outfile:
                json.dump(data_to_use, outfile)
            print("Created webapp JSON: {}".format(json_filename_webapp))

            # CMAA compatibility: write report to Reports/{sha256}_static.json
            try:
                if hasattr(args, 'apk_file') and args.apk_file and os.path.exists(args.apk_file):
                    md5, sha1, sha256, sha512 = get_hashes_by_filename(args.apk_file)
                    for r_dir in ["./Reports", os.path.join(os.path.dirname(os.path.abspath(__file__)), "Reports")]:
                        if not os.path.exists(r_dir):
                            try:
                                os.makedirs(r_dir)
                            except:
                                pass
                        cmaa_json_path = os.path.join(r_dir, "{}_static.json".format(sha256))
                        with open(cmaa_json_path, 'w') as outfile:
                            json.dump(merge_dict_tw, outfile)
                        print("Created CMAA JSON report: {}".format(cmaa_json_path))
            except Exception as e:
                print("Failed to create CMAA JSON report: {}".format(e))

            # Create test.json files for both languages (for web UI buttons)
            # Write to parent directory (Frida/) where webapp.py reads from
            frida_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

            # English version (default for backward compatibility)
            test_json_path = os.path.join(frida_dir, 'test.json')
            with codecs.open(test_json_path, 'w', encoding='utf-8') as outfile:
                json.dump(merge_dict_en, outfile, ensure_ascii=False, indent=2)
            print("Created test.json (English): {}".format(test_json_path))

            # Chinese version
            test_zh_json_path = os.path.join(frida_dir, 'test_zh.json')
            with codecs.open(test_zh_json_path, 'w', encoding='utf-8') as outfile:
                json.dump(merge_dict_tw, outfile, ensure_ascii=False, indent=2)
            print("Created test_zh.json (Chinese): {}".format(test_zh_json_path))

            # Load the selected language for further processing
            load_path = test_json_path if lang == 'en' else test_zh_json_path
            with codecs.open(load_path, 'r', encoding='utf-8') as infile:
                test = json.load(infile, object_pairs_hook=OrderedDict)

            # Generate PDF (uncomment to enable)
            # res = req.post(output_pdf_url, json=data_to_use, timeout=5)
            # pdf_filename = "{}_{}_{}.pdf".format(package_name, args.username, lang_suffix)
            # with open(pdf_filename, 'wb') as f:
            #     f.write(res.content)
            # print("Generated PDF: {}".format(pdf_filename))

            return True
        except Exception as e:
            print(e)
            return False
    

class EfficientStringSearchEngine:
    """
            Usage:
                    1.create an EfficientStringSearchEngine instance (only one should be enough)
                    2.addSearchItem
                    3.search
                    4.get_search_result_by_match_id or get_search_result_dict_key_classname_value_methodlist_by_match_id
    """

    def __init__(self):
        self.__prog_list = []
        self.__dict_result_identifier_to_search_result_list = {}

    def addSearchItem(self, match_id, search_regex_or_fix_string_condition, isRegex):
        self.__prog_list.append(
            (match_id, search_regex_or_fix_string_condition,
             isRegex))  # "root" checking

    def search(self, vm, allstrings_list):
        """
                Example prog list input:
                        [ ("match1", re.compile("PRAGMA\s*key\s*=", re.I), True), ("match2", re.compile("/system/bin/"), True), ("match3", "/system/bin/", False) ]

                Example return (Will always return the corresponding key, but the value is return only when getting the result):
                        { "match1": [ (Complete_String_found, EncoddedMethod), (Complete_String_found, EncoddedMethod) ] , "match2": [] }
        """

        # [String Search Performance Profiling]
        #string_finding_start = datetime.now()

        self.__dict_result_identifier_to_search_result_list.clear()

        for identifier, _, _ in self.__prog_list:  # initializing the return result list
            if identifier not in self.__dict_result_identifier_to_search_result_list:
                self.__dict_result_identifier_to_search_result_list[
                    identifier] = []

        dict_string_value_to_idx_from_file_mapping = {}

        # get a dictionary of string value and string idx mapping
        for idx_from_file, string_value in vm.get_all_offset_from_file_and_string_value_mapping(
        ):
            dict_string_value_to_idx_from_file_mapping[
                string_value] = idx_from_file

        # [String Search Performance Profiling]
        #string_loading_end = datetime.now()
        #print("Time for loading String: " + str(((string_loading_end - string_finding_start).total_seconds())))

        list_strings_idx_to_find = []  # string idx list
        dict_string_idx_to_identifier = {}  # Example: (52368, "match1")

        # Get the searched strings into search idxs
        for line in allstrings_list:
            for identifier, regexp, isRegex in self.__prog_list:
                if (isRegex and regexp.search(line)) or ((not isRegex) and
                                                         (regexp == line)):
                    if line in dict_string_value_to_idx_from_file_mapping:  # Find idx by string
                        string_idx = dict_string_value_to_idx_from_file_mapping[
                            line]
                        list_strings_idx_to_find.append(string_idx)
                        dict_string_idx_to_identifier[string_idx] = identifier

        list_strings_idx_to_find = set(
            list_strings_idx_to_find)  # strip duplicated items

        # [String Search Performance Profiling]
        #string_finding_end = datetime.now()
        #print("Time for finding String: " + str((string_finding_end - string_finding_start).total_seconds()))

        if list_strings_idx_to_find:
            cm = vm.get_class_manager()
            for method in vm.get_methods():
                for i in method.get_instructions(
                ):  # method.get_instructions(): Instruction
                    # 0x1A = "const-string", 0x1B = "const-string/jumbo"
                    if (i.get_op_value() == 0x1A) or (
                            i.get_op_value() == 0x1B):
                        ref_kind_idx = cm.get_offset_idx_by_from_file_top_idx(
                            i.get_ref_kind())
                        if ref_kind_idx in list_strings_idx_to_find:  # find string_idx in string_idx_list
                            if ref_kind_idx in dict_string_idx_to_identifier:
                                original_identifier_name = dict_string_idx_to_identifier[
                                    ref_kind_idx]
                                self.__dict_result_identifier_to_search_result_list[
                                    original_identifier_name].append(
                                        (i.get_string(), method))

        # [String Search Performance Profiling]
        #elapsed_string_finding_time = datetime.now() - string_finding_start
        #print("String Search Elapsed time: " + str(elapsed_string_finding_time.total_seconds()))
        # print("------------------------------------------------------------")

        return self.__dict_result_identifier_to_search_result_list

    def get_search_result_by_match_id(self, match_id):
        return self.__dict_result_identifier_to_search_result_list[match_id]

    def get_search_result_dict_key_classname_value_methodlist_by_match_id(
            self, match_id):
        """
                Input: [ (Complete_String_found, EncoddedMethod), (Complete_String_found, EncoddedMethod) ] or []
                Output: dicionary key by class name
        """
        dict_result = {}

        search_result_value = self.__dict_result_identifier_to_search_result_list[
            match_id]

        try:
            if search_result_value:  # Found the corresponding url in the code
                result_list = set(search_result_value)

                for _, result_method in result_list:  # strip duplicated item
                    class_name = result_method.get_class_name()
                    if class_name not in dict_result:
                        dict_result[class_name] = []

                    dict_result[class_name].append(result_method)
        except KeyError:
            pass

        return dict_result


class FilteringEngine:
    def __init__(self, enable_exclude_classes,
                 str_regexp_type_excluded_classes):
        self.__enable_exclude_classes = enable_exclude_classes
        self.__str_regexp_type_excluded_classes = str_regexp_type_excluded_classes
        self.__regexp_excluded_classes = re.compile(
            self.__str_regexp_type_excluded_classes, re.I)

    def get_filtering_regexp(self):
        return self.__regexp_excluded_classes

    def filter_efficient_search_result_value(self, result):

        if result is None:
            return []
        if (not self.__enable_exclude_classes):
            return result

        l = []
        for found_string, method in result:
            if not self.__regexp_excluded_classes.match(
                    method.get_class_name()):
                l.append((found_string, method))

        return l

    def is_class_name_not_in_exclusion(self, class_name):
        if self.__enable_exclude_classes:
            if self.__regexp_excluded_classes.match(class_name):
                return False
            else:
                return True
        else:
            return True

    def is_all_of_key_class_in_dict_not_in_exclusion(self, dict_result):
        if self.__enable_exclude_classes:
            isAllMatchExclusion = True
            for class_name, method_list in dict_result.items():
                # any match
                if not self.__regexp_excluded_classes.match(class_name):
                    isAllMatchExclusion = False

            if isAllMatchExclusion:
                return False

            return True
        else:
            return True

    def filter_list_of_methods(self, method_list):
        if self.__enable_exclude_classes and method_list:
            l = []
            for method in method_list:
                if not self.__regexp_excluded_classes.match(
                        method.get_class_name()):
                    l.append(method)
            return l
        else:
            return method_list

    def filter_list_of_classes(self, class_list):
        if self.__enable_exclude_classes and class_list:
            l = []
            for i in class_list:
                if not self.__regexp_excluded_classes.match(i):
                    l.append(i)
            return l
        else:
            return class_list

    def filter_list_of_paths(self, vm, paths):
        if self.__enable_exclude_classes and paths:
            cm = vm.get_class_manager()

            l = []
            for path in paths:
                src_class_name, src_method_name, src_descriptor = path.get_src(cm)
                if not self.__regexp_excluded_classes.match(src_class_name):
                    l.append(path)

            return l
        else:
            return paths

    def filter_dst_class_in_paths(self, vm, paths, excluded_class_list):
        cm = vm.get_class_manager()

        l = []
        for path in paths:
            dst_class_name, _, _ = path.get_dst(cm)
            if dst_class_name not in excluded_class_list:
                l.append(path)

        return l

    def filter_list_of_variables(self, vm, paths):
        """
                Example paths input: [[('R', 8), 5050], [('R', 24), 5046]]
        """

        if self.__enable_exclude_classes and paths:
            l = []
            for path in paths:
                access, idx = path[0]
                m_idx = path[1]
                method = vm.get_cm_method(m_idx)
                class_name = method[0]

                if not self.__regexp_excluded_classes.match(class_name):
                    l.append(path)
            return l
        else:
            return paths

    # dic: key=>class_name, value=>paths
    def get_class_container_dict_by_new_instance_classname_in_paths(
            self, vm, analysis, paths, result_idx):
        dic_classname_to_paths = {}
        paths = self.filter_list_of_paths(vm, paths)
        for i in analysis.trace_Register_value_by_Param_in_source_Paths(
                vm, paths):
            # If parameter 0 is a class_container type (ex: Lclass/name;)
            if (i.getResult()[result_idx] is
                    None) or (not i.is_class_container(result_idx)):
                continue
            class_container = i.getResult()[result_idx]
            class_name = class_container.get_class_name()
            if class_name not in dic_classname_to_paths:
                dic_classname_to_paths[class_name] = []
            dic_classname_to_paths[class_name].append(i.getPath())
        return dic_classname_to_paths


class ExpectedException(Exception):
    def __init__(self, err_id, message):
        self.err_id = err_id
        self.message = message

    def __str__(self):
        return "[" + self.err_id + "] " + self.message

    def get_err_id(self):
        return self.err_id

    def get_err_message(self):
        return self.message


class StringHandler:
    def __init__(self, initial_str=""):
        self.str = initial_str

    def __repr__(self):
        return self.str

    def __str__(self):
        return self.str

    def append(self, new_string):
        self.str += new_string

    def appendNewLine(self):
        self.str += "\n"

    def get(self):
        return self.str


def toNdkFileFormat(name):
    return "lib" + name + ".so"


def get_protectionLevel_string_by_protection_value_number(num):
    if num == PROTECTION_NORMAL:
        return "normal"
    elif num == PROTECTION_DANGEROUS:
        return "dangerous"
    elif num == PROTECTION_SIGNATURE:
        return "signature"
    elif num == PROTECTION_SIGNATURE_OR_SYSTEM:
        return "signatureOrSystem"
    else:
        return num


def isBase64(base64_string):
    return re.match('^[A-Za-z0-9+/]+[=]{0,2}$', base64_string)


def isSuccessBase64DecodedString(base64_string):
    # Punct: \:;/-.,?=<>+_()[]{}|"'~`*
    return re.match(
        '^[A-Za-z0-9\\\:\;\/\-\.\,\?\=\<\>\+\_\(\)\[\]\{\}\|\"\'\~\`\*]+$',
        base64_string)


def isNullOrEmptyString(input_string, strip_whitespaces=False):
    if input_string is None:
        return True
    if strip_whitespaces:
        if input_string.strip() == "":
            return True
    else:
        if input_string == "":
            return True
    return False


def dump_NDK_library_classname_to_ndkso_mapping_ndk_location_list(
        list_NDK_library_classname_to_ndkso_mapping):
    l = []
    for ndk_location, path in list_NDK_library_classname_to_ndkso_mapping:
        l.append(ndk_location)
    return l


def get_hashes_by_filename(filename):
    md5 = None
    sha1 = None
    sha256 = None
    sha512 = None
    with open(filename,'rb') as f:
        data = f.read()
        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        sha512 = hashlib.sha512(data).hexdigest()
    return md5, sha1, sha256, sha512


def is_class_implements_interface(cls, search_interfaces, compare_type):
    class_interfaces = cls.get_interfaces()
    if class_interfaces is None:
        return False
    if compare_type == TYPE_COMPARE_ALL:  # All
        for i in search_interfaces:
            if i not in class_interfaces:
                return False
        return True
    elif compare_type == TYPE_COMPARE_ANY:  # Any
        for i in search_interfaces:
            if i in class_interfaces:
                return True
        return False


def get_method_ins_by_superclass_and_method(vm, super_classes, method_name,
                                            method_descriptor):
    for cls in vm.get_classes():
        if cls.get_superclassname() in super_classes:
            for method in cls.get_methods():
                if (method.get_name() == method_name) and (
                        method.get_descriptor() == method_descriptor):
                    yield method


def get_method_ins_by_implement_interface_and_method(
        vm, implement_interface, compare_type, method_name, method_descriptor):
    """
            Example result:
                    (Ljavax/net/ssl/HostnameVerifier; Ljava/io/Serializable;)
    """

    for cls in vm.get_classes():
        if is_class_implements_interface(cls, implement_interface,
                                         compare_type):
            for method in cls.get_methods():
                if (method.get_name() == method_name) and (
                        method.get_descriptor() == method_descriptor):
                    yield method


def get_method_ins_by_implement_interface_and_method_desc_dict(
        vm, implement_interface, compare_type,
        method_name_and_descriptor_list):

    dict_result = {}

    for cls in vm.get_classes():
        if is_class_implements_interface(cls, implement_interface,
                                         compare_type):
            class_name = cls.get_name()
            if class_name not in dict_result:
                dict_result[class_name] = []

            for method in cls.get_methods():
                name_and_desc = method.get_name() + method.get_descriptor()
                if name_and_desc in method_name_and_descriptor_list:
                    dict_result[class_name].append(method)

    return dict_result


def is_kind_string_in_ins_method(method, kind_string):
    for ins in method.get_instructions():
        try:
            if ins.get_kind_string() == kind_string:
                return True
        except AttributeError:  # Because the instruction may not have "get_kind_string()" method
            return False
    return False


def get_all_components_by_permission(xml, permission):
    """
        Return: 
            (1) activity
            (2) activity-alias
            (3) service
            (4) receiver
            (5) provider
        who use the specific permission
    """

    find_tags = [
        "activity", "activity-alias", "service", "receiver", "provider"
    ]
    dict_perms = {}

    for tag in find_tags:
        for item in xml.getElementsByTagName(tag):
            if (item.getAttribute("android:permission") == permission) or (
                    item.getAttribute("android:readPermission") == permission
            ) or (item.getAttribute("android:writePermission") == permission):
                if tag not in dict_perms:
                    dict_perms[tag] = []
                dict_perms[tag].append(item.getAttribute("android:name"))
    return dict_perms


def parseArgument():
    parser = argparse.ArgumentParser(
        description=
        'Maldroid Framework - Android App Security Vulnerability Scanner')
    parser.add_argument(
        "-f",
        "--apk_file",
        help="APK File to analyze",
        type=str,
        required=True)
    parser.add_argument(
        "-m",
        "--analyze_mode",
        help="Specify \"single\"(default) or \"massive\"",
        type=str,
        required=False,
        default=ANALYZE_MODE_SINGLE)
    parser.add_argument(
        "-b",
        "--analyze_engine_build",
        help="Analysis build number.",
        type=int,
        required=False,
        default=ANALYZE_ENGINE_BUILD_DEFAULT)
    parser.add_argument(
        "-t",
        "--analyze_tag",
        help="Analysis tag to uniquely distinguish this time of analysis.",
        type=str,
        required=False,
        default=None)
    parser.add_argument(
        "-e",
        "--extra",
        help=
        "1)Do not check(default)  2)Check  security class names, method names and native methods",
        type=int,
        required=False,
        default=1)
    parser.add_argument(
        "-c",
        "--line_max_output_characters",
        help="Setup the maximum characters of analysis output in a line",
        type=int,
        required=False)
    parser.add_argument(
        "-s",
        "--store_analysis_result_in_db",
        help=
        "Specify this argument if you want to store the analysis result in MongoDB. Please add this argument if you have MongoDB connection.",
        action="store_true")
    parser.add_argument(
        "-v",
        "--show_vector_id",
        help=
        "Specify this argument if you want to see the Vector ID for each vector.",
        action="store_true")
    # [Json] filename 
    parser.add_argument(
        "-n",
        "--filename",
        help=
        "transport filename(base64) from web for show PDF",
        required=True
    )
    # [generate_pdf] pdf output username
    parser.add_argument(
        "-u",
        "--username",
        help=
        "username",
        required=True
    )
    # [Language] Report language selection
    parser.add_argument(
        "-l",
        "--lang",
        help=
        "Report language: 'zh-TW' for Traditional Chinese, 'en' for English (default: en)",
        type=str,
        required=False,
        choices=['zh-TW', 'zh', 'en'],
        default='en'
    )
    # When you want to use "report_output_dir", remember to use "os.path.join(args.report_output_dir, [filename])"
    parser.add_argument(
        "-o",
        "--report_output_dir",
        help="Analysis Report Output Directory",
        type=str,
        required=False,
        default=DIRECTORY_REPORT_OUTPUT)

    args = parser.parse_args()
    return args


        


# ------------------------------------------------------------------------
# Androguard server communication functions
BASE_URL = 'http://localhost:8010/androguard'

def get_androguard(endpoint, params=None):
    """
    Make a request to the androguard server API.
    
    Args:
        endpoint (str): The API endpoint to call
        params (dict): Optional parameters for the request
        
    Returns:
        dict: JSON response from the server, or None if error
    """
    try:
        url = "{}{}".format(BASE_URL, endpoint)
        print("Making request to: {}".format(url))
        response = requests.get(url, params=params)
        print("Response status code: {}".format(response.status_code))
        if response.status_code == 200:
            result = response.json()
            #print("Response JSON: {}".format(result))
            return result
        else:
            print("Error: Received response with status code", response.status_code)
            print("Response text: {}".format(response.text))
            return None
    except Exception as e:
        print("An error occurred:", str(e))
        return None

   
def lab_results_to_dict(lab_result):
    """Flatten a lab result's 'results' list-of-dicts into a single dict."""

    d = {}
    if lab_result and "results" in lab_result:
        for item in lab_result["results"]:
            if isinstance(item, dict):
                d.update(item)
    return d


def __analyze(writer, args):
    """
            Exception:
                    apk_file_not_exist
                    classes_dex_not_in_apk
    """

    print("[DEBUG] __analyze function started")
    # StopWatch: Counting execution time...
    stopwatch_start = datetime.now()

    efficientStringSearchEngine = EfficientStringSearchEngine()
    filteringEngine = FilteringEngine(ENABLE_EXCLUDE_CLASSES,
                                      STR_REGEXP_TYPE_EXCLUDE_CLASSES)

    isUsingSQLCipher = False
    isMasterKeyVulnerability = False

    if args.line_max_output_characters is None:
        if platform.system().lower() == "windows":
            args.line_max_output_characters = LINE_MAX_OUTPUT_CHARACTERS_WINDOWS - \
                LINE_MAX_OUTPUT_INDENT
        else:
            args.line_max_output_characters = LINE_MAX_OUTPUT_CHARACTERS_LINUX - \
                LINE_MAX_OUTPUT_INDENT

    if not os.path.isdir(args.report_output_dir):
        os.mkdir(args.report_output_dir)

    writer.writeInf_ForceNoPrint("analyze_mode", args.analyze_mode)
    writer.writeInf_ForceNoPrint("analyze_engine_build",
                                 args.analyze_engine_build)
    if args.analyze_tag:
        writer.writeInf_ForceNoPrint("analyze_tag", args.analyze_tag)

    APK_FILE_NAME_STRING = DIRECTORY_APK_FILES + args.apk_file
    apk_Path = APK_FILE_NAME_STRING  # + ".apk"

    if (".." in args.apk_file):
        raise ExpectedException(
            "apk_file_name_slash_twodots_error",
            "APK file name should not contain slash(/) or two dots(..) (File: "
            + apk_Path + ").")

    if not os.path.isfile(apk_Path):
        raise ExpectedException("apk_file_not_exist",
                                "APK file not exist (File: " + apk_Path + ").")

    if args.store_analysis_result_in_db:
        try:
            imp.find_module('pymongo')
            found_pymongo_lib = True
        except ImportError:
            found_pymongo_lib = False

        if not found_pymongo_lib:
            pass

            # Cause some unexpected behavior on Linux => Temporarily comment it out
            # raise ExpectedException("libs_not_found_pymongo", "Python library \"pymongo\" is not found. Please install the library first: http://api.mongodb.org/python/current/installation.html.")

    #apk_filepath_relative = apk_Path
    apk_filepath_absolute = os.path.abspath(apk_Path)

    #writer.writeInf_ForceNoPrint("apk_filepath_relative", apk_filepath_relative)
    writer.writeInf_ForceNoPrint("apk_filepath_absolute",
                                 apk_filepath_absolute)

    apk_file_size = float(os.path.getsize(apk_filepath_absolute)) / (
        1024 * 1024)
    writer.writeInf_ForceNoPrint("apk_file_size", apk_file_size)

    writer.update_analyze_status("loading_apk")

    writer.writeInf_ForceNoPrint("time_starting_analyze", datetime.utcnow())

    a = apk.APK(apk_Path)

    #---------------------------------Ian--------------------
    # d,dx=androlyze.AnalyzeDex(a.get_dex(),raw=True,decompiler=decompiler)
    #----------------------------------------

    writer.update_analyze_status("starting_apk")

    package_name = a.get_package()
    global DYLANPACKAGENAME
    DYLANPACKAGENAME = package_name

    if isNullOrEmptyString(package_name, True):
        # Log warning but continue with default package name instead of throwing exception
        package_name = "unknown_app"
        writer.writeInf_ForceNoPrint(
            "package_name_empty",
            "Package name is empty (File: " + apk_Path + "). Using default: unknown_app")
        print("[package_name_empty] Package name is empty (File: " + apk_Path + ").")

    writer.writeInf("platform", "Android", "Platform")
    writer.writeInf("package_name", str(package_name), "Package Name")

    # Check: http://developer.android.com/guide/topics/manifest/manifest-element.html
    if not isNullOrEmptyString(a.get_androidversion_name()):
        try:
            writer.writeInf("package_version_name",
                            str(a.get_androidversion_name()),
                            "Package Version Name")
        except:
            writer.writeInf("package_version_name",
                            a.get_androidversion_name().encode(
                                'ascii', 'ignore'), "Package Version Name")

    if not isNullOrEmptyString(a.get_androidversion_code()):
        # The version number shown to users. This attribute can be set as a raw string or as a reference to a string resource.
        # The string has no other purpose than to be displayed to users.
        try:
            writer.writeInf("package_version_code",
                            int(a.get_androidversion_code()),
                            "Package Version Code")
        except ValueError:
            writer.writeInf("package_version_code",
                            a.get_androidversion_code(),
                            "Package Version Code")

    if len(a.get_dex()) == 0:
        raise ExpectedException(
            "classes_dex_not_in_apk",
            "Broken APK file. \"classes.dex\" file not found (File: " +
            apk_Path + ").")

    try:
        str_min_sdk_version = a.get_min_sdk_version()
        if (str_min_sdk_version is None) or (str_min_sdk_version == ""):
            raise ValueError
        else:
            int_min_sdk = int(str_min_sdk_version)
            writer.writeInf("minSdk", int_min_sdk, "Min Sdk")
    except ValueError:
        # Check: http://developer.android.com/guide/topics/manifest/uses-sdk-element.html
        # If "minSdk" is not set, the default value is "1"
        writer.writeInf("minSdk", 1, "Min Sdk")
        int_min_sdk = 1

    try:
        str_target_sdk_version = a.get_target_sdk_version()
        if (str_target_sdk_version is None) or (str_target_sdk_version == ""):
            raise ValueError
        else:
            int_target_sdk = int(str_target_sdk_version)
            writer.writeInf("targetSdk", int_target_sdk, "Target Sdk")
    except ValueError:
        # Check: http://developer.android.com/guide/topics/manifest/uses-sdk-element.html
        # If not set, the default value equals that given to minSdkVersion.
        int_target_sdk = int_min_sdk

    md5, sha1, sha256, sha512 = get_hashes_by_filename(APK_FILE_NAME_STRING)
    writer.writeInf("file_md5", md5, "MD5   ")
    writer.writeInf("file_sha1", sha1, "SHA1  ")
    writer.writeInf("file_sha256", sha256, "SHA256")
    writer.writeInf("file_sha512", sha512, "SHA512")

    writer.update_analyze_status("starting_dvm")

    d = dvm.DalvikVMFormat(a.get_dex())

    writer.update_analyze_status("starting_analyze")

    vmx = analysis.VMAnalysis(d)

    writer.update_analyze_status("starting_maldroid")

    analyze_start = datetime.now()


    classes_result = get_androguard('/classes')
    if classes_result and isinstance(classes_result, dict) and 'classes' in classes_result:
        all_classes = classes_result['classes']
        #print("Retrieved {} classes from androguard server".format(len(all_classes)))
        #print("all_classes: {}".format(all_classes))
    else:
        print("Failed to get classes from androguard server, using empty list")
        all_classes = []


    # Get permissions from androguard server instead of local analysis
    permissions_result = get_androguard('/permissions')
    if permissions_result and isinstance(permissions_result, dict) and 'permissions' in permissions_result:
        all_permissions = permissions_result['permissions']
        #print("Retrieved {} permissions from androguard server".format(len(all_permissions)))
    else:
        print("Failed to get permissions from androguard server, using empty list")
        all_permissions = []
    
    # Get strings from androguard server instead of local analysis
    strings_result = get_androguard('/strings')
    if strings_result and isinstance(strings_result, dict) and 'strings' in strings_result:
        allstrings = strings_result['strings']
        #print("Retrieved {} strings from androguard server".format(len(allstrings)))
        #print("allstrings: {}".format(allstrings))
    else:
        print("Failed to get strings from androguard server, using empty list")
        allstrings = []

    # Get file from androguard server instead of local analysis
    files_result = get_androguard('/files')
    if files_result and isinstance(files_result, dict) and 'files' in files_result:
        allfiles = files_result['files']
        #print("Retrieved {} files from androguard server".format(len(allfiles)))
        #print("allfiles: {}".format(allfiles))
    else:
        print("Failed to get files from androguard server, using empty list")
        allfiles = []



    allurls_strip_duplicated = []
    
    


    # ------------------------------------------------------------------------
    #[Important: String Efficient Searching Engine]
    # >>>>STRING_SEARCH<<<<
    # addSearchItem params: 
    # (1)match_id  
    # (2)regex or string(url or string you want to find)
    # (3)is using regex for parameter 2
    efficientStringSearchEngine.addSearchItem("$__possibly_check_root__",
                                              re.compile("/system/bin"),
                                              True)  # "root" checking
    efficientStringSearchEngine.addSearchItem("$__possibly_check_su__", "su",
                                              False)  # "root" checking2
    efficientStringSearchEngine.addSearchItem(
        "$__sqlite_encryption__", re.compile("PRAGMA\s*key\s*=", re.I),
        True)  # SQLite encryption checking

    print("Start Detection") # 1404 ~ 4561
    print("------------------------------------------------------------")

    # Print all urls without SSL:
    exception_url_string = [
        "http://example.com", "http://example.com/", "http://www.example.com",
        "http://www.example.com/", "http://www.google-analytics.com/collect",
        "http://www.google-analytics.com", "http://hostname/?",
        "http://hostname/"
    ]
    
    for line in allstrings:
        if re.match('http\:\/\/(.+)', line):  # ^https?\:\/\/(.+)$
            allurls_strip_duplicated.append(line)

    allurls_strip_non_duplicated = sorted(set(allurls_strip_duplicated))
    allurls_strip_non_duplicated_final = []

    if allurls_strip_non_duplicated:
        for url in allurls_strip_non_duplicated:
            if (url not in exception_url_string) and (not url.startswith("http://schemas.android.com/")) and \
                (not url.startswith("http://www.w3.org/")) and \
                (not url.startswith("http://apache.org/")) and \
                (not url.startswith("http://xml.org/")) and \
                (not url.startswith("http://localhost/")) and \
                (not url.startswith("http://java.sun.com/")) and \
                (not url.endswith("/namespace")) and \
                (not url.endswith("-dtd")) and \
                (not url.endswith(".dtd")) and \
                (not url.endswith("-handler")) and \
                    (not url.endswith("-instance")):
                # >>>>STRING_SEARCH<<<<
                efficientStringSearchEngine.addSearchItem(
                    url, url, False)  # use url as "key"

                allurls_strip_non_duplicated_final.append(url)
    
    # ------------------------------------------------------------------------
    # [Json]
    report_dict_zhtw["md5"] = md5
    report_dict_zhtw["sha256"] = sha256
    report_dict_zhtw["timestamp"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    report_dict_zhtw["file_name"] = str(base64.b64decode(args.filename))
    report_dict_zhtw["app_name"] = str(package_name)
    report_dict_zhtw["app_version"] = str(a.get_androidversion_name())
    report_dict_zhtw["package_version_code"] = str(a.get_androidversion_code())
    report_dict_zhtw["min_sdk"] = str(int_min_sdk)
    report_dict_zhtw["target_sdk"] = str(int_target_sdk)
    report_dict_zhtw["url_list"] = allurls_strip_non_duplicated_final

    report_dict_en["md5"] = md5
    report_dict_en["sha256"] = sha256
    report_dict_en["timestamp"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    report_dict_en["file_name"] = str(base64.b64decode(args.filename))
    report_dict_en["app_name"] = str(package_name)
    report_dict_en["app_version"] = str(a.get_androidversion_name())
    report_dict_en["package_version_code"] = str(a.get_androidversion_code())
    report_dict_en["min_sdk"] = str(int_min_sdk)
    report_dict_en["target_sdk"] = str(int_target_sdk)
    report_dict_en["url_list"] = allurls_strip_non_duplicated_final
    
    # ------------------------------------------------------------------------

    # Base64 String decoding:
    base64_mapping = {}
    excluded_strings = [
        "endsWith", "allCells", "fillList", "endNanos", "cityList", "cloudid=",
        "Liouciou"
    ]

    for line in allstrings:
        # check if the line is base64 encoded
        if not (isBase64(line) and len(line) >= 3):
            continue
            
        # check if the line is in excluded strings
        if line in excluded_strings:
            continue
            
        try:
            decoded_string = base64.b64decode(line)
            
            # check if the decoded string is valid and has enough length
            if (isSuccessBase64DecodedString(decoded_string) and 
                len(decoded_string) > 3 and 
                decoded_string not in base64_mapping):
                
                base64_mapping[decoded_string] = line
                # >>>>STRING_SEARCH<<<<
                efficientStringSearchEngine.addSearchItem(line, line, False)
                
        except (TypeError, ValueError):
            # only catch Base64 decoding related exceptions
            pass
        
    # ------------------------------------------------------------------------

    # >>>>STRING_SEARCH<<<<
    # start the search core engine
    efficientStringSearchEngine.search(d, allstrings)

    # ------------------------------------------------------------------------
    # Androguard server communication (using global get_androguard function)
    # ------------------------------------------------------------------------
    # [lab_001] - SSL / Cleartext HTTP Traffic Detection (migrated to androguard_server)
    # 三層架構: AndroidManifest usesCleartextTraffic + Network Security Config + smali source->sink
    result_lab001 = get_androguard('/lab_001')

    if result_lab001 and isinstance(result_lab001, dict) and result_lab001.get('has_finding'):
        verdict_001     = result_lab001.get('verdict', 'WARNING')
        findings_001    = result_lab001.get('findings', [])
        orphan_001      = result_lab001.get('orphan_urls', [])
        nsc             = result_lab001.get('nsc_summary', {})
        manifest_attr   = result_lab001.get('manifest_attr_value')
        target_sdk      = result_lab001.get('target_sdk', 0)
        effective_allow = result_lab001.get('effective_cleartext_allowed', True)
        all_http        = result_lab001.get('all_http_urls', [])

        if verdict_001 == 'CRITICAL':
            level_001 = LEVEL_CRITICAL
        elif verdict_001 == 'WARNING':
            level_001 = LEVEL_WARNING
        else:
            level_001 = LEVEL_INFO

        writer.startWriter(
            "LAB_001_CLEARTEXT_TRAFFIC", level_001,
            u"[AS-lab001][MAS-4.1.2.4.1][MASVS-NETWORK-1][CWE-319] SSL Connection / Cleartext Traffic 檢查",
            u"偵測到 App 可能透過 cleartext (HTTP) 進行網路傳輸,違反 MAS-4.1.2.4.1。"
            u"本檢查分三層: (1) AndroidManifest 的 android:usesCleartextTraffic 設定;"
            u"(2) res/xml network_security_config 的 base-config / domain-config;"
            u"(3) Smali bytecode 的 source -> sink 同 method 配對(http URL 字串 + WebView.loadUrl / "
            u"HttpURLConnection / OkHttp / Volley 等網路 sink)。"
            u"CRITICAL: http URL 確實流入網路 sink; WARNING: 找到 http URL 但同 method 無 sink; "
            u"INFO: manifest 已禁止 cleartext 但 code 仍含 http URL。"
            u" Ref: https://developer.android.com/training/articles/security-config"
            + "||" +
            u"App may transmit data over cleartext HTTP, violating MAS-4.1.2.4.1. Three layers checked: "
            u"(1) AndroidManifest android:usesCleartextTraffic, (2) res/xml network_security_config "
            u"(base-config / domain-config), (3) smali source->sink pairing of http URL strings with "
            u"network sinks (WebView.loadUrl / HttpURLConnection / OkHttp / Volley). "
            u"CRITICAL: http URL flows to a network sink; WARNING: http URL found without co-located sink; "
            u"INFO: manifest disables cleartext but http URLs still in code."
            u" Ref: https://developer.android.com/training/articles/security-config",
            ["SSL_Security", "Cleartext"])

        writer.write(u"[Manifest] usesCleartextTraffic=%s  targetSdk=%s  effective_allowed=%s" % (
            manifest_attr if manifest_attr is not None else "not set",
            target_sdk, effective_allow))

        if nsc.get('present'):
            writer.write(u"[NSC] base_cleartext=%s  domain_configs=%d" % (
                nsc.get('base_cleartext'), len(nsc.get('domain_configs', []))))
            for dc in nsc.get('domain_configs', []):
                writer.write(u"  domain_config cleartext=%s  domains=%s" % (
                    dc.get('cleartext'), ", ".join(dc.get('domains', []))))

        if findings_001:
            writer.write(u"[CRITICAL findings: %d]" % len(findings_001))
            for f in findings_001:
                cls = f.get('class', '')
                if cls.startswith('L') and cls.endswith(';'):
                    cls = cls[1:-1].replace('/', '.')
                writer.write(u"  %s.%s()  url=%s  sinks=%s" % (
                    cls, f.get('method', ''), f.get('url', ''),
                    ",".join(f.get('sinks', []))))

        if orphan_001:
            writer.write(u"[WARNING orphan http URLs: %d (no sink in same method)]" % len(orphan_001))
            for o in orphan_001[:20]:
                cls = o.get('class', '')
                if cls.startswith('L') and cls.endswith(';'):
                    cls = cls[1:-1].replace('/', '.')
                writer.write(u"  %s.%s()  url=%s" % (
                    cls, o.get('method', ''), o.get('url', '')))
            if len(orphan_001) > 20:
                writer.write(u"  ... and %d more" % (len(orphan_001) - 20))

        # keep PDF report's url_list in sync with server-detected http URLs
        if all_http:
            report_dict_zhtw["url_list"] = all_http
            report_dict_en["url_list"]   = all_http

    # Testing androguard server 
    # find_method_params = {
    #     'classname': 'Lcom/example/staticlabapp/SecurityTestMethods;',
    #     'methodname': 'aesEncrypt'
    # }
    # result = get_androguard('/find_method', find_method_params)
    # print("Androguard server response:", result)
    # if result and result.get("method_found"):
    #     print("Found aesEncrypt - maldroid_main.py")
    # else:
    #     print("Notfound aesEncrypt - maldroid_main.py")
    #--------------------------------------------------------------------
    # [lab_002] - Security methods finding

    
    result = get_androguard('/lab02')

    #if args.extra == 2:  # The output may be too verbose, so make it an option
    list_security_related_methods = []
    
    # Use AndroguardServer response 
    if result and isinstance(result, dict):
        methods = result.get('results', [])
        print("Processing AndroguardServer response...")
        print("Number of methods found: {}".format(result.get('count', 0)))
        for method_info in methods:
            list_security_related_methods.append(method_info)
    else:
        print("No AndroguardServer response available, skipping security methods analysis")

    if list_security_related_methods:
        print("Lab002: Security_Methods Found")
        writer.startWriter(
            "Security_Methods", LEVEL_NOTICE,
            u"[AS-lab002][OWASP-V1.9,V1.10,V3.4][MAST-4.2.3][工-9.9.9] 安全相關 Methods 檢查",
            u"找到安全相關 method 名稱" + "||" + u"Find the security-related method name")
        
        for method in list_security_related_methods:
            class_name = method.get('class_name', '')
            method_name = method.get('method_name', '')
            writer.write(method_name)
    
    #------------------------------------------------------------------------------------------------------
    # [lab_003] - Security classes finding

    # Use AndroguardServer API for LAB03
    result_classes = get_androguard('/lab03')
    list_security_related_classes = []
    
    # Use AndroguardServer response for classes
    if result_classes and isinstance(result_classes, dict):
        classes = result_classes.get('results', [])
        print("Processing AndroguardServer LAB03 response...")
        print("Number of classes found: {}".format(result_classes.get('count', 0)))
        for class_info in classes:
            list_security_related_classes.append(class_info)
            print("class_info: {}".format(class_info))

    if list_security_related_classes:
        print("Lab003: Security_Classes Found")
        print("list_security_related_classes: {}".format(list_security_related_classes))
        writer.startWriter(
            "Security_Classes", LEVEL_NOTICE,
            u"[AS-lab003][OWASP-V1.9,V1.10,V3.4][MAST-4.2.3][工-9.9.9] 安全相關 Classes 檢查",
            u"找到安全相關 class 的名稱:" + "||" + u"Find the security-related class name")

        for class_info in list_security_related_classes:
            # API response dictionary
            class_name = class_info.get('class_name', '')
            writer.write(class_name)

    #------------------------------------------------------------------------------------------------------
    # [lab_004](/**/) - In-app billing: by Dylan

    billing = 'com.android.vending.BILLING'
    if billing in all_permissions:
        writer.startWriter(
            "com.android.vending.BILLING", LEVEL_INFO,
            u"[AS-lab004][OWASP-V6.1][MAST-4.2.1][工-4.1.3.1] 存取權限 'com.android.vending.BILLING' ",
            u"只在付費app中出現。" + "||" + u"Only appears in paid apps.")

    pkg_billing = vmx.get_tainted_packages().search_packages(
        "Lcom/android/vending/billing/IInAppBillingService")
    pkg_billing = filteringEngine.filter_list_of_paths(d, pkg_billing)
    path_purchases = vmx.get_tainted_packages().search_methods(
        ".", "getPurchases", ".")
    path_setpackage = vmx.get_tainted_packages().search_methods(
        ".", "setPackage", ".")
    if pkg_billing:
        writer.startWriter(
            "method getPurchases()", LEVEL_INFO,
            u"[AS-lab004][OWASP-V6.1][MAST-4.2.1][工-4.1.3.1] 發現 package 'Lcom/android/vending/billing/IInAppBillingService' ",
            u"此 app 有 google play 的內部付費購買功能。" + "||" + u"This app has google play's internal paid purchase feature.")
        writer.show_Paths(d, path_purchases)

    #----------------------------------------------------------------------------------------------------
    # [lab_005] - android_Permissions: READ_CONTACTS

    # Read contact by Ian
    contact = 'android.permission.READ_CONTACTS'
    if contact in all_permissions:
        writer.startWriter(
            "READ_CONTACTS", LEVEL_NOTICE,
            "[AS-lab005][Bank-001][OWASP-V6.1][MAST-4.2.1][工-9.9.9] android.permission.READ_CONTACTS",
            u"存取權限 'android.permission.READ_CONTACTS'，需要存取通訊錄之 app 才會出現" + "||" + u"Access permission 'android.permission.READ_CONTACTS', which will only appear for apps that need to access the address book")
        writer.write("Permission detected: " + contact)

    #----------------------------------------------------------------------------------------------------
    # [lab_006] - android_Permissions: Read_Call_Log
 
    calllog = 'android.permission.READ_CALL_LOG'
    if calllog in all_permissions:
        writer.startWriter(
            "READ_CALL_LOG", LEVEL_NOTICE,
            "[AS-lab006][Bank-002][OWASP-V6.1][MAST-4.2.1][工-9.9.9] android.permission.READ_CALL_LOG",
            u"存取權限 'android.permission.READ_CALL_LOG'，需要存取通聯紀錄之 app 才會出現" + "||" + u"Access permission 'android.permission.READ_CALL_LOG', which will only appear if the app needs to access the contact log")
        writer.write("Permission detected: " + calllog)
    
    #----------------------------------------------------------------------------------------------------
    # [lab_007] - android_Permissions(Read GPS): ACCESS_FINE_LOCATION

    gpslocation = 'android.permission.ACCESS_FINE_LOCATION'
    if gpslocation in all_permissions:
        writer.startWriter(
            "ACCESS_FINE_LOCATION", LEVEL_NOTICE,
            "[AS-lab007][Bank-003][OWASP-V6.1][MAST-4.2.1][工-9.9.9] android.permission.ACCESS_FINE_LOCATION",
            u"存取權限 'android.permission.ACCESS_FINE_LOCATION'，需要存取 GPS 之 app 才會出現" + "||" + u"Access permission 'android.permission.ACCESS_FINE_LOCATION', which will only appear if the app needs to access the GPS")
        writer.write("Permission detected: " + gpslocation)
    
    #----------------------------------------------------------------------------------------------------
    # [lab_008] - android_Permissions(Read GPS): sending GPS messages

    # Use androguard find_method to check for LocationManager.requestLocationUpdates
    gps_method_found = False
    try:
        params = {
            'classname': 'Landroid/location/LocationManager;',
            'methodname': 'requestLocationUpdates'
        }
        result = get_androguard('/find_method', params)
        if result and result.get('method_found', False):
            gps_method_found = True
    except Exception as e:
        print("Error checking for GPS method: {}".format(str(e)))

    if gps_method_found:
        writer.startWriter(
            "SENSITIVE_gps", LEVEL_NOTICE,
            u"[AS-lab008][OWASP-V2.2][MAST-4.2.2][工-9.9.9] 傳送 GPS 訊息的 code",
            u"此 app 有傳送 GPS 訊息的程式碼 (LocationManager.requestLocationUpdates):" + "||" + u"This app has code for sending GPS messages (LocationManager.requestLocationUpdates):"
        )
        writer.write("GPS method detected: LocationManager.requestLocationUpdates")

    #----------------------------------------------------------------------------------------------------
    # [lab_009] - android_Permissions(Read SMS): ACCESS_FINE_LOCATION

    sms = 'android.permission.READ_SMS'
    if sms in all_permissions:
        writer.startWriter(
            "READ_SMS", LEVEL_NOTICE,
            u"[AS-lab009][Bank-004][OWASP-V6.1][MAST-4.2.1][工-9.9.9] android.permission.READ_SMS",
            u"存取權限 'android.permission.READ_SMS'，需要存取 SMS 之 app 才會出現" + "||" + u"Access permission 'android.permission.READ_SMS', which will appear only for apps that need to access SMS")
        writer.write("Permission detected: " + sms)

    #----------------------------------------------------------------------------------------------------
    # [lab_010] - android_Permissions(Record voice): RECORD_AUDIO

    record = 'android.permission.RECORD_AUDIO'
    if record in all_permissions:
        writer.startWriter(
            "RECORD_AUDIO", LEVEL_NOTICE,
            u"[AS-lab010][OWASP-V6.1][MAST-4.2.1][Bank-005][工-9.9.9] android.permission.RECORD_AUDIO",
            u"存取權限 'android.permission.RECORD_AUDIO'，需要 Record 之 app 才會出現" + "||" + u"Access permission 'android.permission.RECORD_AUDIO', need Record's app to appear")
        writer.write("Permission detected: " + record)

    #----------------------------------------------------------------------------------------------------
    # [lab_011] - content://media (RECORD_AUDIO): 
 
    # Use allstrings from androguard server (already retrieved above)
    allmuri = []
    for line in allstrings:
        if "content://media" in line:
            allmuri.append(line)
    if allmuri:
        print("allmuri: {}".format(allmuri))
        print("LAB_011: Found {} media URI strings".format(len(allmuri)))
        writer.startWriter("URi", LEVEL_NOTICE,
                           u"[AS-lab011][Bank-006] 具有 media 的 URI 字串",
                           u"此 app 有 media 的 URI 字串" + "||" + u"This app has the URI string for media")
    for oneuri in allmuri:
        writer.write(oneuri + "\t")

    #----------------------------------------------------------------------------------------------------
    # [lab_012] - APP String (URI): 

    alluri = []
    for line in allstrings:
        if "content://" in line:
            alluri.append(line)
    if alluri:
        writer.startWriter("URi", LEVEL_NOTICE, 
                           u"[AS-lab012][Bank-007] 具有 URI 字串",
                           u"此 app 有 URI 字串" + "||" + u"This app has the URI string")
        for oneuri in alluri:
            writer.write(oneuri + "\t")

    #----------------------------------------------------------------------------------------------------
    # [lab_013] - APP String (URL):

    # Use allstrings from androguard server (already retrieved above)
    allurl = []
    for line in allstrings:
        if re.search("^((https?|ftp)://[^\s/$.?#].[^\s]*)$", line):
            allurl.append(line)
    # IP=vm.get_regex_strings("[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+") #ip

    if allurl:
        writer.startWriter("URL", LEVEL_NOTICE, 
                           u"[AS-lab013][Bank-008] 具有 URL 字串",
                           u"此 app 有 URL 字串" + "||" + u"This app has the URL string")
    for oneurl in allurl:
        writer.write(oneurl + "\t")
    
    #----------------------------------------------------------------------------------------------------
    # [lab_014] - APP String (IP):

    allip = []
    for line in allstrings:
        if re.search("[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", line):
            allip.append(line)

    if allip:
        writer.startWriter("IP found", LEVEL_NOTICE,
                           u"[AS-lab014][Bank-009] 具有 IP 字串",
                           u"此 app 有 IP 字串" + "||" + u"This app has the IP string")
    for oneip in allip:
        writer.write(oneip + "\t")
        
    #----------------------------------------------------------------------------------------------------
    # [lab_015] - APP String (Email):

    allemail = []
    for line in allstrings:
        if re.search("(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])", line):
            allemail.append(line)

    if allemail:
        writer.startWriter("E-mail found", LEVEL_NOTICE,
                           u"[AS-lab015] 具有 E-mail 字串",
                           u"此 app 有 E-mail 字串" + "||" + u"This app has the E-mail string")
    # Avoid PDf crash
    # for oneemail in allemail:
    #     writer.write(oneemail + "\t")

    #-----------------------------------------------------------------------------------

    # [lab_016] CVE-2023-4863 libwebp VP8LBuildHuffmanTable Heap Overflow
    # Scan native .so files in the APK for vulnerable libwebp strings

    lab016Result = get_androguard('/lab_016')

    if lab016Result and lab016Result.get('has_vulnerability') == True:
        print("lab_016 VULNERABLE - CVE-2023-4863 detected")
        vulnerable_files = [r['file'] for r in lab016Result.get('results', []) if r.get('status') == 'VULNERABLE']
        matched_strings = []
        for r in lab016Result.get('results', []):
            if r.get('status') == 'VULNERABLE':
                matched_strings.extend(r.get('matched_strings', []))
        matched_strings = list(set(matched_strings))

        writer.startWriter(
            "CVE_2023_4863_LIBWEBP", LEVEL_CRITICAL,
            u"[AS-lab016] CVE-2023-4863 libwebp Heap Overflow 檢測",
            u"此 app 的 native library 中偵測到含有 CVE-2023-4863 漏洞的 libwebp。攻擊者可透過惡意 WebP 圖片觸發 VP8LBuildHuffmanTable heap overflow，導致任意程式碼執行。建議更新 libwebp 至 1.3.2 以上版本。\n 參考: https://nvd.nist.gov/vuln/detail/CVE-2023-4863 " + "||" + \
            u"Vulnerable libwebp native library detected (CVE-2023-4863). An attacker can trigger a VP8LBuildHuffmanTable heap overflow via a crafted WebP image, leading to arbitrary code execution. Update libwebp to version 1.3.2 or later.\n refer to: https://nvd.nist.gov/vuln/detail/CVE-2023-4863",
            ["CVE-2023-4863", "libwebp", "HeapOverflow", "NativeLibrary"])
        writer.write(u"Affected files: " + ", ".join(vulnerable_files) + u"\nMatched strings: " + ", ".join(matched_strings))
    else:
        print("lab_016 pass - No CVE-2023-4863 vulnerability found")

    #------------------------------------------------------------------------------------------------------
    # [lab_017] - DEBUGGABLE checking:

    is_debug_open = a.is_debuggable()  # Check 'android:debuggable'
    if is_debug_open:
        writer.startWriter(
            "DEBUGGABLE", LEVEL_CRITICAL,
            u"[AS-lab017][OWASP-V7.3,V7.4][MAST-4.2.5][M4] Android Debug Mode 檢查",
            u"DEBUG 模式在 AndroidManifest.xml 中是打開的 (android:debuggable=\"true\")。這是非常危險的，攻擊者可以藉由 LOGCAT 偵測 Debug 訊息。如果它是已釋出 app 請將 Debug 模式關閉。" + "||" + u"DEBUG mode turned on in AndroidManifest.xml (android:debuggable=\"true\"). This is very dangerous, as attackers can use LOGCAT to detect debug messages. If it is a released app, please turn off Debug mode.",
            ["Debug"])

    # else:
    #     writer.startWriter(
    #         u"DEBUGGABLE", LEVEL_INFO,
    #         "[AS-lab017][OWASP-V7.3,V7.4][MAST-4.2.5][M4] Android Debug Mode 檢查",
    #         u"DEBUG 模式在 AndroidManifest.xml 中是關閉的 (android:debuggable=\"false\")。",
    #         ["Debug"])

    #------------------------------------------------------------------------------------------------------

    # Checking whether the app is checking debuggable:
    """
		Java code checking debuggable:
			boolean isDebuggable = (0 != (getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE));
			if (isDebuggable) { }

		Smali code checking debuggable:
			invoke-virtual {p0}, Lcom/example/androiddebuggable/MainActivity;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;
			move-result-object v1
			iget v1, v1, Landroid/content/pm/ApplicationInfo;->flags:I
			and-int/lit8 v1, v1, 0x2
			if-eqz v1, :cond_0

		Checking Pattern:
			1. Find tainted calling field: Landroid/content/pm/ApplicationInfo;->flags:I
			2. Get the next instruction of the calling field: Landroid/content/pm/ApplicationInfo;->flags:I
			3. Check whether the next instruction is 0xDD(and-int/lit8) and make sure the register numbers are all matched
				iget [[v1]], v1, [[[Landroid/content/pm/ApplicationInfo;->flags:I]]]
				and-int/lit8 v1, [[v1]], [0x2]
	"""
    # list_detected_FLAG_DEBUGGABLE_path = []
    # field_ApplicationInfo_flags_debuggable = vmx.get_tainted_field(
    #     "Landroid/content/pm/ApplicationInfo;", "flags", "I")

    # if field_ApplicationInfo_flags_debuggable:
    #     for path, stack in field_ApplicationInfo_flags_debuggable.get_paths_and_stacks(
    #             d, filteringEngine.get_filtering_regexp()):
    #         last_one_ins = stack.gets()[-1]
    #         last_two_ins = stack.gets()[-2]

    #         if (last_one_ins is not None) and (last_two_ins is not None):
    #             try:
    #                 # and-int/lit8 vx,vy,lit8
    #                 if (last_one_ins[0] == 0xDD) and (
    #                         last_two_ins[1][0][1] == last_one_ins[1][1][1]
    #                 ) and (last_one_ins[1][2][1] == 2):
    #                     list_detected_FLAG_DEBUGGABLE_path.append(path)
    #                 """
	# 					Example 1:
	# 						last_two_ins => [82, [(0, 1), (0, 1), (258, 16, 'Landroid/content/pm/ApplicationInfo;->flags I')]]
	# 						last_one_ins => [221, [(0, 1), (0, 1), (1, 2)]]

	# 					Example 2:
	# 						last_two_ins => [82, [(0, 2), (0, 0), (258, 896, 'Landroid/content/pm/ApplicationInfo;->flags I')]]
	# 						last_one_ins => [221, [(0, 2), (0, 2), (1, 2)]]

	# 					Java code:
	# 						stack.show()
	# 						print(last_one_ins)
	# 						print(last_two_ins)
	# 				"""
    #             except:
    #                 pass

    # if list_detected_FLAG_DEBUGGABLE_path:
    #     writer.startWriter(
    #         u"HACKER_DEBUGGABLE_CHECK", LEVEL_NOTICE,
    #         u"[LAB-005] 檢查 Android Debug Mode的code",
    #         u"在 AndroidManifest.xml 中發現程式碼 \"ApplicationInfo.FLAG_DEBUGGABLE\" :",
    #         ["Debug", "Hacker"])

    #     for path in list_detected_FLAG_DEBUGGABLE_path:
    #         writer.show_single_PathVariable(d, path)
    # else:
    #     writer.startWriter(
    #         u"HACKER_DEBUGGABLE_CHECK", LEVEL_INFO,
    #         u"[LAB-005]檢查 Android Debug Mode的code",
    #         u"沒有在 AndroidManifest.xml 中發現程式碼 \"ApplicationInfo.FLAG_DEBUGGABLE\"",
    #         ["Debug", "Hacker"])

    #----------------------------------------------------------------------------------
    # [lab_018] - FileProvider 不當設定檢測 (Improper FileProvider Configuration)

    lab018Result = get_androguard('/lab_018')

    if lab018Result and lab018Result.get('has_vulnerability') == True:
        print("Lab18 VULNERABLE - Improper FileProvider configuration detected")

        vulnerabilities = lab018Result.get('results', [])

        # Script 
        issues_summary = []
        for vuln in vulnerabilities:
            issues_summary.append("[{0}] {1}: {2}".format(vuln['severity'], vuln['file'], vuln['issue']))

        writer.startWriter(
            "FILEPROVIDER_MISCONFIGURATION", LEVEL_CRITICAL,
            u"[AS-lab018][OWASP MASVS-STORAGE] FileProvider 不當設定",
            u"偵測到 FileProvider 不當設定，可能導致檔案或目錄意外曝露。包含:\n" +
            u"\n".join(issues_summary) +
            u"\n\n建議:\n1. 不使用 <root-path>\n2. 避免分享廣泛路徑 (. 或 /)\n3. 謹慎使用 <external-path>" +
            "||" +
            u"Improper FileProvider configuration detected, may expose files/directories. Issues found:\n" +
            u"\n".join(issues_summary) +
            u"\n\nRecommendations:\n1. Don't use <root-path>\n2. Avoid broad path sharing (. or /)\n3. Use <external-path> carefully",
            ["FileProvider", "Storage", "Configuration"])

        # 顯示詳細資訊
        for vuln in vulnerabilities:
            writer.write("File: {0}\nIssue: {1}\nSeverity: {2}\nDescription: {3}\n".format(
                vuln['file'], vuln['issue'], vuln['severity'], vuln['description']))
    else:
        print("Lab18 pass - No FileProvider misconfiguration found")
    # #         u"USE_PERMISSION_ACCESS_MOCK_LOCATION", LEVEL_INFO,
    # #         u"[AS-lab018] 不必要的權限檢查",
    # #         u"權限 'android.permission.ACCESS_MOCK_LOCATION' 有被正確地設定。")

    #----------------------------------------------------------------------------------
    # [lab_019] - : permissionNameOfWrongPermissionGroup:
    permissionNameOfWrongPermissionGroup = a.get_permission_tag_wrong_settings_names()

    if permissionNameOfWrongPermissionGroup:  # If the list is not empty
        writer.startWriter(
            u"PERMISSION_GROUP_EMPTY_VALUE", LEVEL_CRITICAL,
            u"[AS-lab019][OWASP-V6.1][MAST-4.2.1] AndroidManifest PermissionGroup Checking",
            u"設定 'permissionGroup' 屬性為空白值將會讓權限的定義變得無效而且其它 app 都不能使用。" + "||" + u"Setting the 'permissionGroup' attribute to a blank value will make the permission definition invalid and unavailable to other apps.")

        for name in permissionNameOfWrongPermissionGroup:
            writer.write("permission name: '%s' is empty in the `permissionGroup`" % (name))
    # else:
    #     writer.startWriter(
    #         u"PERMISSION_GROUP_EMPTY_VALUE", LEVEL_INFO,
    #         "[AS-lab019][OWASP-V6.1][MAST-4.2.1] AndroidManifest PermissionGroup Checking",
    #         u"PermissionGroup 在 AndroidManifest 的 permission tag 中有正確地設定。")

    #----------------------------------------------------------------------------------
    # [lab_020] - use-permission check:

    # Critical use-permission check:
    user_permission_critical_manufacturer = [
        "android.permission.INSTALL_PACKAGES",
        "android.permission.WRITE_SECURE_SETTINGS"
    ]
    user_permission_critical = [
        "android.permission.MOUNT_FORMAT_FILESYSTEMS",
        "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
        "android.permission.RESTART_PACKAGES"
    ]

    list_user_permission_critical_manufacturer = []
    list_user_permission_critical = []

    for permission in all_permissions:
        if permission in user_permission_critical_manufacturer:
            list_user_permission_critical_manufacturer.append(permission)
        if permission in user_permission_critical:
            list_user_permission_critical.append(permission)

    if list_user_permission_critical_manufacturer or list_user_permission_critical:
        if list_user_permission_critical_manufacturer:
            writer.startWriter(
                u"USE_PERMISSION_SYSTEM_APP", LEVEL_CRITICAL,
                u"[AS-lab020][OWASP-V6.1][MAST-4.2.1] AndroidManifest 使用權限確認 ",
                u"此 app 只能被手機製造商或 Google 簽名放在 '/system/app' 下並且釋出。如果不是，這可能是支惡意的 app" + "||" + u"This app can only be signed by the phone manufacturer or Google under '/system/app' and released. If not, this may be a malicious app"
            )

            for permission in list_user_permission_critical_manufacturer:
                writer.write(
                    "System use-permission found: \"" + permission + "\"")

        if list_user_permission_critical:
            writer.startWriter(
                u"USE_PERMISSION_CRITICAL", LEVEL_CRITICAL,
                u"[AS-lab020][OWASP-V6.1][MAST-4.2.1] AndroidManifest 使用權限確認",
                u"這 app 要求很高的權限，請小心使用" + "||" + "This app requires very high privileges, so please use it carefully")

            for permission in list_user_permission_critical:
                writer.write(
                    "Critical use-permission found: \"" + permission + "\"")
    # else:
    #     writer.startWriter(
    #         u"USE_PERMISSION_SYSTEM_APP", LEVEL_INFO,
    #         u"[AS-lab020][OWASP-V6.1][MAST-4.2.1][LAB-008] AndroidManifest 使用權限確認",
    #         u"沒有系統等級的使用權限。")

    #----------------------------------------------------------------------------------
    # [lab_021] - android.permission: (INTERNET)

#     isSuggestGCM = False
#     if int_min_sdk is not None:
#         if int_min_sdk < 8:  # Android 2.2=SDK 8
#             isSuggestGCM = True

#     if isSuggestGCM:

#         output_string = """Your supporting minSdk is """ + str(
#             int_min_sdk) + """
# You are now allowing minSdk to less than 8. Please check: http://developer.android.com/about/dashboards/index.html
# Google Cloud Messaging (Push Message) service only allows Android SDK >= 8 (Android 2.2). Pleae check: http://developer.android.com/google/gcm/gcm.html
# You may have the change to use GCM in the future, so please set minSdk to at least 9."""
#         writer.startWriter(u"MANIFEST_GCM", LEVEL_NOTICE,
#                            u"Google Cloud Messaging Suggestion", output_string)

#     else:

#         writer.startWriter(u"MANIFEST_GCM", LEVEL_INFO,
#                            u"Google Cloud Messaging Suggestion",
#                            u"Nothing to suggest.")

    #------------------------------------------------------------------------------------------------------
    # Find network methods:

    # pkg_xxx is a 'PathP' object
    if 'Ljava/net/URLConnection;' in all_classes:
        print("found Java/net/URLConnection in all_classes")
        print("======++++++++++++++++++++++++++++++++++++++++++++++=====================")
        pkg_URLConnection = ['Ljava/net/URLConnection;']  # Convert to list format
    else:
        pkg_URLConnection = []

   
    if 'Ljava/net/HttpURLConnection;' in all_classes:
        print("found Java/net/HttpURLConnection in allpackages")
        print("======++++++++++++++++++++++++++++++++++++++++++++++=====================")
        pkg_HttpURLConnection = ['Ljava/net/HttpURLConnection;']  # Convert to list format
    else:
        pkg_HttpURLConnection = []

    if 'Ljavax/net/ssl/HttpsURLConnection;' in all_classes:
        pkg_HttpsURLConnection = ['Ljavax/net/ssl/HttpsURLConnection;']  # Convert to list format
    else:
        pkg_HttpsURLConnection = []

    if 'Lorg/apache/http/impl/client/DefaultHttpClient;' in all_classes:
        pkg_DefaultHttpClient = ['Lorg/apache/http/impl/client/DefaultHttpClient;']  # Convert to list format
    else:
        pkg_DefaultHttpClient = []

    if 'Lorg/apache/http/client/HttpClient;' in all_classes:
        pkg_HttpClient = ['Lorg/apache/http/client/HttpClient;']  # Convert to list format
    else:
        pkg_HttpClient = []

    #------------------------------
    # pkg_URLConnection = filteringEngine.filter_list_of_paths(
    #     d, pkg_URLConnection)
    # pkg_HttpURLConnection = filteringEngine.filter_list_of_paths(
    #     d, pkg_HttpURLConnection)
    # pkg_HttpsURLConnection = filteringEngine.filter_list_of_paths(
    #     d, pkg_HttpsURLConnection)
    # pkg_DefaultHttpClient = filteringEngine.filter_list_of_paths(
    #     d, pkg_DefaultHttpClient)
    # pkg_HttpClient = filteringEngine.filter_list_of_paths(d, pkg_HttpClient)
    #-------------------------------


    # size_pkg_URLConnection = len(pkg_URLConnection)
    # size_pkg_HttpURLConnection = len(pkg_HttpURLConnection)
    # size_pkg_HttpsURLConnection = len(pkg_HttpsURLConnection)
    # size_pkg_DefaultHttpClient = len(pkg_DefaultHttpClient)
    # size_pkg_HttpClient = len(pkg_HttpClient)

    # Provide 2 options for users:
    # 1.Show the network-related class or not
    # 2.Exclude 'Lcom/google/' package or 'Lcom/facebook/' package  or not
    # **Should Make the output path sorted by class name

    if pkg_URLConnection or pkg_HttpURLConnection or pkg_HttpsURLConnection or pkg_DefaultHttpClient or pkg_HttpClient:
        
      
        # if "android.permission.INTERNET" in all_permissions:
        #     writer.startWriter(u"USE_PERMISSION_INTERNET", LEVEL_INFO,
        #                        u"[LAB-021][OWASP-V5.2][MAST-4.2.3] 網路存取檢查",
        #                        u"此 app 經由 HTTP 協定存取網路")
        # else:
        #     writer.startWriter(
        #         u"USE_PERMISSION_INTERNET", LEVEL_CRITICAL,
        #         u"[LAB-021][OWASP-V5.2][MAST-4.2.3] 網路存取檢查",
        #         u"此 app 有存取網路的程式碼，但在 AndroidManifest 中卻沒有 'android.permission.INTERNET' 的使用權限。"
        #     )
        if 'android.permission.INTERNET' not in all_permissions:
            writer.startWriter(
                u"USE_PERMISSION_INTERNET", LEVEL_CRITICAL,
                u"[AS-lab021][OWASP-V5.2][MAST-4.2.3] 網路存取檢查",
                u"此 app 有存取網路的程式碼，但在 AndroidManifest 中卻沒有 'android.permission.INTERNET' 的使用權限" + "||" + u"This app has code to access the network, but there is no 'android.permission.INTERNET' permission in AndroidManifest"
            )

        # if pkg_URLConnection:
        #     print("        =>URLConnection:")
        #     analysis.show_Paths(d, pkg_URLConnection)
        #     print
        # if pkg_HttpURLConnection:
        #     print("        =>HttpURLConnection:")
        #     analysis.show_Paths(d, pkg_HttpURLConnection)
        #     print
        # if pkg_HttpsURLConnection:
        #     print("        =>HttpsURLConnection:")
        #     analysis.show_Paths(d, pkg_HttpsURLConnection)
        #     print
        # if pkg_DefaultHttpClient:
        #     print("        =>DefaultHttpClient:")
        #     analysis.show_Paths(d, pkg_DefaultHttpClient)
        #     print
        # if pkg_HttpClient:
        #     print("        =>HttpClient:")
        #     analysis.show_Paths(d, pkg_HttpClient)
        #     print

    # else:
    #     writer.startWriter(u"USE_PERMISSION_INTERNET", LEVEL_INFO,
    #                        u"[AS-lab021][OWASP-V5.2][MAST-4.2.3] 網路存取檢查",
    #                        u"沒有發現與網路存取相關的程式碼。")

    # ------------------------------------------------------------------------
    # [lab_022] - Base64-encoded sensitive content detection (migrated to androguard_server)
    # 只報「解碼後是 http URL / secret pattern / 敏感關鍵字」的 Base64
    result_lab022 = get_androguard('/lab_022')

    if result_lab022 and isinstance(result_lab022, dict) and result_lab022.get('has_finding'):
        verdict_022  = result_lab022.get('verdict', 'WARNING')
        critical_022 = result_lab022.get('critical', [])

        if verdict_022 == 'CRITICAL':
            level_022 = LEVEL_CRITICAL
        elif verdict_022 == 'WARNING':
            level_022 = LEVEL_WARNING
        else:
            level_022 = LEVEL_INFO

        writer.startWriter(
            "LAB_022_BASE64_SENSITIVE", level_022,
            u"[AS-lab022][MAS-4.1.2.3.8][MASVS-STORAGE-2][CWE-312] Base64 編碼敏感資料檢查",
            u"偵測 Base64 編碼字串中隱藏的敏感資料。Base64 本身不是漏洞 (圖片、JWT、"
            u"二進位資源都會用),只報『解碼後是真實風險內容』的 Base64: "
            u"CRITICAL (解碼後是 cleartext http:// URL 或 AWS/Google API/JWT secret pattern); "
            u"WARNING (解碼後含 password/api_key/token 等敏感關鍵字)。"
            u"概念上是 lab_074 (明文 secret 偵測) 的 Base64 編碼版本。"
            u" Ref: https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/"
            + "||" +
            u"Detects sensitive data hidden inside Base64-encoded strings. Base64 itself is "
            u"not a vulnerability (icons, JWT, binary resources all use it); only reports Base64 "
            u"whose DECODED content matches real risk patterns: CRITICAL (decoded cleartext http:// "
            u"URL or known secret patterns - AWS/Google API/JWT); WARNING (decoded contains sensitive "
            u"keywords - password/api_key/token). Conceptually the Base64 counterpart of lab_074."
            u" Ref: https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/",
            ["Base64", "Hardcoded"])

        # Only output CRITICAL findings — keep report compact
        if critical_022:
            writer.write(u"[CRITICAL: %d]" % len(critical_022))
            for f in critical_022:
                cls = f.get('class', '')
                if cls.startswith('L') and cls.endswith(';'):
                    cls = cls[1:-1].replace('/', '.')
                writer.write(u"  %s.%s()  reason=%s  decoded=%s" % (
                    cls, f.get('method', ''), f.get('reason', ''),
                    f.get('decoded', '')))

    # ------------------------------------------------------------------------
    # [lab_023] - WebView addJavascriptInterface checking:

    # Don't match class name because it might use the subclass of WebView
    # path_WebView_addJavascriptInterface = vmx.get_tainted_packages(
    # ).search_methods_exact_match(u"addJavascriptInterface",
    #                              "(Ljava/lang/Object; Ljava/lang/String;)V")
    # path_WebView_addJavascriptInterface = filteringEngine.filter_list_of_paths(
    #     d, path_WebView_addJavascriptInterface)

    find_method_params = {
        'classname': 'Landroid/webkit/WebView;',
        'methodname': 'addJavascriptInterface'
    }
    result = get_androguard('/find_method', find_method_params)
    
    # if path_WebView_addJavascriptInterface:
    # response: {"method_found": True}
    if result and result.get("method_found"):
        output_string = u"""找到 WebView \"addJavascriptInterface\" 漏洞，這個方法可以讓 JavaScript 去操縱手機應用程式，這是一個很強大的功能，但對於 API 等級在 JELLY_BEAN (4.2) 以下的系統也代表著具有很大的安全風險，因為 JavaScript 會使用反射(reflection)去訪問物件的公共域(public field)，若網頁包含不可信任的內容，在 WebView 使用可能會造成攻擊者藉由執行植入的 Javascript 程式碼操控手機應用程式。
 
相關文章 : 
  1."http://developer.android.com/reference/android/webkit/WebView.html#addJavascriptInterface(java.lang.Object, java.lang.String) "
  2.https://labs.mwrinfosecurity.com/blog/2013/09/24/webview-addjavascriptinterface-remote-code-execution/
  3.http://50.56.33.56/blog/?p=314
  4.http://blog.trustlook.com/2013/09/04/alert-android-webview-addjavascriptinterface-code-execution-vulnerability/
請修改下列程式碼:"""

        output_string_en = """This method allows JavaScript to manipulate mobile applications, which is a very powerful feature, but represents a significant security risk for systems with API levels below JELLY_BEAN (4.2) because JavaScript uses reflection to access the public field of an object, and if a web page contains untrusted content, using it in WebView may cause an attacker to manipulate the phone application by executing the implanted Javascript code.

Related articles : 
  1. "http://developer.android.com/reference/android/webkit/WebView.html#addJavascriptInterface(java.lang.Object, java.lang.String) "
  2. https://labs.mwrinfosecurity.com/blog/2013/09/24/webview-addjavascriptinterface-remote-code-execution/
  3.http://50.56.33.56/blog/?p=314
  4. http://blog.trustlook.com/2013/09/04/alert-android-webview-addjavascriptinterface-code-execution-vulnerability/
Please modify the following code:"""

        writer.startWriter(
            u"WEBVIEW_RCE", LEVEL_CRITICAL,
            u"[AS-lab023][OWASP-V6.5,V6.8][MAST-4.2.3][工-4.1.5.1.2][CVE-2013-4710] WebView addJavascriptInterface RCE 漏洞檢查",
            output_string + "||" + output_string_en, [u"WebView", u"遠端程式碼執行"], u"CVE-2013-4710")
        # writer.show_Paths(d, path_WebView_addJavascriptInterface)

    # else:

    #     writer.startWriter(
    #         u"WEBVIEW_RCE", LEVEL_INFO,
    #         u"[AS-lab023][OWASP-V6.5,V6.8][MAST-4.2.3][工4.1.5.1.2][CVE-2013-4710]WebView addJavascriptInterface RCE 漏洞檢查",
    #         u"沒有發現 WebView addJavascriptInterface 漏洞。",
    #         [u"WebView", u"Remote Code Execution"], u"CVE-2013-4710")

    # ------------------------------------------------------------------------
    # [lab_024] - KeyStore null PWD checking:

    list_no_pwd_probably_ssl_pinning_keystore = []
    list_no_pwd_keystore = []
    list_protected_keystore = []

    path_KeyStore = vmx.get_tainted_packages(
    ).search_class_methods_exact_match("Ljava/security/KeyStore;", "load",
                                       "(Ljava/io/InputStream; [C)V")
    path_KeyStore = filteringEngine.filter_list_of_paths(d, path_KeyStore)
    for i in analysis.trace_Register_value_by_Param_in_source_Paths(
            d, path_KeyStore):
        if i.getResult()[2] == 0:  # null = 0 = Not using password
            if (i.is_class_container(1)):
                clz_invoked = i.getResult()[1]
                if clz_invoked.get_class_name(
                ) == "Ljava/io/ByteArrayInputStream;":
                    list_no_pwd_probably_ssl_pinning_keystore.append(
                        i.getPath())
                else:
                    list_no_pwd_keystore.append(i.getPath())
            else:
                if i.getResult()[1] == 0:  # null = 0
                    list_no_pwd_probably_ssl_pinning_keystore.append(
                        i.getPath())
                else:
                    list_no_pwd_keystore.append(i.getPath())
        else:
            list_protected_keystore.append(i.getPath())

    if (not list_no_pwd_keystore) and (not list_protected_keystore) and (
            not list_no_pwd_probably_ssl_pinning_keystore):
        pass
        # writer.startWriter(
        #     "HACKER_KEYSTORE_NO_PWD", LEVEL_INFO,
        #     u"[AS-lab024][OWASP-V1.11,V3.1,V3.2,V3.3,V4.4][MAST-4.2.7][工-4.1.2.3.7,4.1.2.3.8] 金鑰保護檢查",
        #     u"忽略檢查金鑰檔案，因為金鑰被密碼保護或是並沒有使用到金鑰。", ["KeyStore", "Hacker"])

    else:
        if list_no_pwd_probably_ssl_pinning_keystore:

            writer.startWriter(
                "HACKER_KEYSTORE_SSL_PINNING", LEVEL_CRITICAL,
                u"[AS-lab024][OWASP-V1.11,V3.1,V3.2,V3.3,V4.4][MAST-4.2.7][工-4.1.2.3.7,4.1.2.3.8] 金鑰保護檢查",
                u"以下的金鑰檔案似乎是使用 \"byte array\" 或 \"hard-coded cert info\" 來時做 SSL 的憑證綁定 (總共: "+ str(len(list_no_pwd_probably_ssl_pinning_keystore)) +u")，請手動檢查:" + "||" + \
                u"The following key files seem to use \"byte array\" or \"hard-coded cert info\" when doing SSL certificate binding (total: "+ str(len(list_no_pwd_probably_ssl_pinning_keystore)) +u"), Please check manually:", 
                ["KeyStore", "Hacker"])

            for keystore in list_no_pwd_probably_ssl_pinning_keystore:
                writer.show_Path(d, keystore)

        if list_no_pwd_keystore:

            writer.startWriter(
                "HACKER_KEYSTORE_NO_PWD", LEVEL_CRITICAL,
                u"[AS-lab024][OWASP-V1.11,V3.1,V3.2,V3.3,V4.4][MAST-4.2.7][工-4.1.2.3.7,4.1.2.3.8] 金鑰保護檢查",
                u"以下的金鑰檔案似乎沒有被密碼保護住 (總共: " + str(len(list_no_pwd_keystore)) + u")，請手動檢查:" + "||" + \
                u"The following key files do not seem to be password protected (total: " + str(len(list_no_pwd_keystore)) + u"), Please check manually:",
                ["KeyStore", "Hacker"])

            for keystore in list_no_pwd_keystore:
                writer.show_Path(d, keystore)

        if list_protected_keystore:

            writer.startWriter(
                "HACKER_KEYSTORE_SSL_PINNING2", LEVEL_NOTICE,
                u"[AS-lab024][OWASP-V1.11,V3.1,V3.2,V3.3,V4.4][MAST-4.2.7][工-4.1.2.3.7,4.1.2.3.8] 金鑰保護資訊",
                u"以下的金鑰檔案似乎被密碼保護並且有使用 SSL 的憑證綁定(總共: " + str(len(list_protected_keystore)) + u")，你可以使用 \"Portecle\" 的工具來管理金鑰檔案的憑證:" + "||" + \
                u"The following key files appear to be password protected and have certificates bound using SSL (total: " + str(len(list_protected_keystore)) + u"), you can use the tool \"Portecle\" to manage the credentials of the key files:",
                ["KeyStore", "Hacker"])

            for keystore in list_protected_keystore:
                writer.show_Path(d, keystore)

    # ------------------------------------------------------------------------
    # [lab_025] - Find all keystore

    list_keystore_file_name = []
    list_possible_keystore_file_name = []

    for name, _, _ in a.get_files_information():
        """
                1.Name includes cert (search under /res/raw)
                2.ends with .bks (search all)
        """
        if name.endswith(".bks") or name.endswith(".jks"):
            # If any files found on "/res" dir, only get from "/res/raw"
            if (name.startswith("res/")) and (not name.startswith("res/raw/")):
                continue
            list_keystore_file_name.append(name)
        elif ("keystore" in name) or ("cert" in name):
            # If any files found on "/res" dir, only get from "/res/raw
            if (name.startswith("res/")) and (not name.startswith("res/raw/")):
                continue
            list_possible_keystore_file_name.append(name)

    if list_keystore_file_name or list_possible_keystore_file_name:
        if list_keystore_file_name:
            writer.startWriter("HACKER_KEYSTORE_LOCATION1", LEVEL_NOTICE,
                               u"[AS-lab025] 存取網路檢查金鑰檔案位置", 
                               u"BKS 金鑰檔案:" + "||" + "BKS Key File:",
                               ["KeyStore", "Hacker"])
            for i in list_keystore_file_name:
                writer.write(i)

        if list_possible_keystore_file_name:
            writer.startWriter("HACKER_KEYSTORE_LOCATION2", LEVEL_NOTICE,
                               u"[AS-lab025] 可能金鑰檔案位置", 
                               u"BKS 可能的金鑰檔案:" + "||" + "BKS possible key file:",
                               ["KeyStore", "Hacker"])
            for i in list_possible_keystore_file_name:
                writer.write(i)
    # else:
    #     writer.startWriter(
    #         "HACKER_KEYSTORE_LOCATION1", LEVEL_INFO, u"[AS-lab025] 金鑰檔案位置",
    #         u"沒有找到任何可能的 BKS 金鑰檔案或是金鑰檔案的證書 (注意: 這並不代表此 app 沒有使用任何的金鑰檔案):",
    #         ["KeyStore", "Hacker"])

    # ------------------------------------------------------------------------
    # BKS KeyStore checking:
    # """
	# 	Example:
	#     const-string v11, "BKS"
	#     invoke-static {v11}, Ljava/security/KeyStore;->getInstance(Ljava/lang/String;)Ljava/security/KeyStore;
	# """

    # list_Non_BKS_keystore = []
    # path_BKS_KeyStore = vmx.get_tainted_packages(
    # ).search_class_methods_exact_match(
    #     "Ljava/security/KeyStore;", "getInstance",
    #     "(Ljava/lang/String;)Ljava/security/KeyStore;")
    # path_BKS_KeyStore = filteringEngine.filter_list_of_paths(
    #     d, path_BKS_KeyStore)
    # for i in analysis.trace_Register_value_by_Param_in_source_Paths(
    #         d, path_BKS_KeyStore):
    #     if i.getResult()[0] is None:
    #         continue
    #     if (i.is_string(
    #             i.getResult()[0])) and ((i.getResult()[0]).upper() != "BKS"):
    #         list_Non_BKS_keystore.append(i.getPath())

    # if list_Non_BKS_keystore:
    #  writer.startWriter("KEYSTORE_TYPE_CHECK", LEVEL_CRITICAL, u"[LAB-011]金鑰格式檢查", u"Android 只接受 'BKS' 格式的 KeyStore(金鑰檔案). 請確認你是使用 'BKS' 格式的 金鑰檔案:", ["KeyStore"])
    #  for keystore in list_Non_BKS_keystore:
    #  writer.show_Path(d, keystore)
    # else:
    #  writer.startWriter("KEYSTORE_TYPE_CHECK", LEVEL_INFO, u"[LAB-011]金鑰格式檢查", u"金鑰檔案 'BKS' 的格式檢查 OK", ["KeyStore"])

    # ------------------------------------------------------------------------
    # [lab_026] - Android PackageInfo signatures checking:
    """
		Example:

		    move-result-object v0
		    iget-object v2, v0, Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;

			PackageManager pkgManager = context.getPackageManager();
			pkgManager.getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES).signatures[0].toByteArray();
	"""

    list_PackageInfo_signatures = []
    path_PackageInfo_signatures = vmx.get_tainted_packages(
    ).search_class_methods_exact_match(
        "Landroid/content/pm/PackageManager;", "getPackageInfo",
        "(Ljava/lang/String; I)Landroid/content/pm/PackageInfo;")
    path_PackageInfo_signatures = filteringEngine.filter_list_of_paths(
        d, path_PackageInfo_signatures)
    for i in analysis.trace_Register_value_by_Param_in_source_Paths(
            d, path_PackageInfo_signatures):
        if i.getResult()[2] is None:
            continue
        if i.getResult()[2] == 64:
            list_PackageInfo_signatures.append(i.getPath())

    if list_PackageInfo_signatures:
        writer.startWriter(
            "HACKER_SIGNATURE_CHECK", LEVEL_NOTICE,
            u"[AS-lab026][OWASP-V1.12][MAST-4.2.5][M10] 檢查是否獲取 package 簽名",
            u"此 app 在程式裡有檢查 package 的簽名，這可以檢查 app 是否被攻擊者駭入" + "||" + \
            u"This app has a signature in the program to check the package, which can check if the app was hacked by the attacker",
            ["Signature", "Hacker"])
        for signature in list_PackageInfo_signatures:
            writer.show_Path(d, signature)
    # else:
    #     writer.startWriter(
    #         "HACKER_SIGNATURE_CHECK", LEVEL_INFO,
    #         u"[AS-lab026][OWASP-V1.12][MAST-4.2.5][M10] 檢查是否獲取 package 簽名",
    #         u"沒有偵測到此 app 在程式中有檢查 package 的簽名", ["Signature", "Hacker"])

    # ------------------------------------------------------------------------
    # [lab_027] - Developers preventing screenshot capturing checking:
    """
		Example:
		    const/16 v1, 0x2000
		    invoke-super {p0, p1}, Landroid/support/v7/app/AppCompatActivity;->onCreate(Landroid/os/Bundle;)V
		    invoke-virtual {p0}, Lcom/example/preventscreencapture/MainActivity;->getWindow()Landroid/view/Window;
		    move-result-object v0
		    invoke-virtual {v0, v1, v1}, Landroid/view/Window;->setFlags(II)V


			getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
	"""

    list_code_for_preventing_screen_capture = []

    
    # path_code_for_preventing_screen_capture = vmx.get_tainted_packages(
    # ).search_class_methods_exact_match("Landroid/view/Window;", "setFlags",
    #                                    "(I I)V")
    # path_code_for_preventing_screen_capture = filteringEngine.filter_list_of_paths(
    #     d, path_code_for_preventing_screen_capture)
    # for i in analysis.trace_Register_value_by_Param_in_source_Paths(
    #         d, path_code_for_preventing_screen_capture):
    #     if (i.getResult()[1] is None) or (i.getResult()[2] is None):
    #         continue
    #     if (not isinstance(i.getResult()[1], (int, long))) or (not isinstance(
    #             i.getResult()[2], (int, long))):
    #         continue
    #     if (i.getResult()[1] & 0x2000) and (i.getResult()[2] & 0x2000):
    #         list_code_for_preventing_screen_capture.append(i.getPath())
    flagsResult = get_androguard('/lab_27')
    if flagsResult:
        list_code_for_preventing_screen_capture = flagsResult['results']
    else:
        list_code_for_preventing_screen_capture = []
    
    # check if the flag is 0x2000
    has_0x2000_flag = False
    print(list_code_for_preventing_screen_capture)
    if list_code_for_preventing_screen_capture:
        for item in list_code_for_preventing_screen_capture:
            if item.get('flag_value') == '0x2000':
                has_0x2000_flag = True
                break
    
    if has_0x2000_flag:
        print(list_code_for_preventing_screen_capture)
       
        writer.startWriter(
            "HACKER_PREVENT_SCREENSHOT_CHECK", LEVEL_NOTICE,
            u"[AS-lab027][OWASP-V2.7][MAST-4.2.3][工4.1.2.3.9][M4] 防止螢幕擷取的設定",
            u"""此 app 有防止螢幕擷取的設定，範例:getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);這可以讓開發者用來保護 app""" + "||" + \
            u"""This app has settings to prevent screen capture, example: getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE); this allows the developer to use to protect the app""",
            ["Hacker"])
    # else:
    #     writer.startWriter(
    #         "HACKER_PREVENT_SCREENSHOT_CHECK", LEVEL_INFO,
    #         u"[AS-lab027][OWASP-V2.7][MAST-4.2.3][工4.1.2.3.9][M4] 防止螢幕擷取的設定",
    #         u"沒有偵測到這個 app 有防止螢幕擷取的設定", ["Hacker"])

    # ------------------------------------------------------------------------
    # [lab_028] - Runtime exec checking:
    """
		Example Java code:
			1. Runtime.getRuntime().exec("");
			2. Runtime rr = Runtime.getRuntime(); Process p = rr.exec("ls -al");
		    
		Example Bytecode code (The same bytecode for those two Java code):
			const-string v2, "ls -al"
		    invoke-virtual {v1, v2}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;
	"""

    exec_result = get_androguard('/lab_28')

    if exec_result and isinstance(exec_result, dict) and exec_result.get('has_finding'):
        verdict_028  = exec_result.get('verdict', 'WARNING')
        critical_028 = exec_result.get('critical', [])
        warning_028  = exec_result.get('warning', [])
        info_028     = exec_result.get('info', [])

        if verdict_028 == 'CRITICAL':
            level_028 = LEVEL_CRITICAL
        elif verdict_028 == 'WARNING':
            level_028 = LEVEL_WARNING
        else:
            level_028 = LEVEL_INFO

        writer.startWriter(
            "LAB_028_RUNTIME_EXEC", level_028,
            u"[AS-lab028][MAS-4.1.5.1.1][MASVS-CODE-4][CWE-78] Runtime.exec / ProcessBuilder 指令執行檢查",
            u"偵測到 App 使用 Runtime.getRuntime().exec() 或 new ProcessBuilder() 執行外部指令。"
            u"本檢查抓出每個呼叫的命令字串並分級: "
            u"CRITICAL (命令為變數 -> Command Injection 風險), "
            u"WARNING (硬編碼命令但非 root detection -> 需人工 review), "
            u"INFO (硬編碼命令屬於 root detection 範圍如 su / which su / busybox 等 -> 屬合法防護機制)。"
            u" Ref: https://cwe.mitre.org/data/definitions/78.html"
            + "||" +
            u"App uses Runtime.getRuntime().exec() or new ProcessBuilder() to run external commands. "
            u"Findings are classified into: CRITICAL (dynamic command argument -> command injection risk), "
            u"WARNING (hardcoded command, not root-detection -> manual review needed), "
            u"INFO (hardcoded root-detection commands like su / which su / busybox -> legitimate defense)."
            u" Ref: https://cwe.mitre.org/data/definitions/78.html",
            ["Command", "Injection"])

        if critical_028:
            writer.write(u"[CRITICAL: dynamic command argument: %d]" % len(critical_028))
            for f in critical_028:
                cls = f.get('class', '')
                if cls.startswith('L') and cls.endswith(';'):
                    cls = cls[1:-1].replace('/', '.')
                writer.write(u"  %s.%s()  api=%s  cmd=%s" % (
                    cls, f.get('method', ''), f.get('api', ''), f.get('command', '')))

        if warning_028:
            writer.write(u"[WARNING: hardcoded command needs review: %d]" % len(warning_028))
            for f in warning_028:
                cls = f.get('class', '')
                if cls.startswith('L') and cls.endswith(';'):
                    cls = cls[1:-1].replace('/', '.')
                writer.write(u"  %s.%s()  api=%s  cmd=%s" % (
                    cls, f.get('method', ''), f.get('api', ''), f.get('command', '')))

        if info_028:
            writer.write(u"[INFO: root-detection commands: %d]" % len(info_028))
            for f in info_028:
                cls = f.get('class', '')
                if cls.startswith('L') and cls.endswith(';'):
                    cls = cls[1:-1].replace('/', '.')
                writer.write(u"  %s.%s()  api=%s  cmd=%s" % (
                    cls, f.get('method', ''), f.get('api', ''), f.get('command', '')))
    # if list_Runtime_exec :
    #  writer.startWriter("COMMAND_SU", LEVEL_CRITICAL, u"[MAST-4.2.3][LAB-012]Runtime Critical Command Checking(Runtime指令檢查)", u"Requesting for \"root\" permission code sections 'Runtime.getRuntime().exec(\"su\")' found (Critical but maybe false positive)[發現需要root權限的code區段Runtime.getRuntime().exec(\"su\")' (可能具有危險)]:", ["Command"])

    #  for path in list_Runtime_exec:
    #  writer.show_Path(d, path)
    # else:
    #  writer.startWriter("COMMAND", LEVEL_INFO, u"[MAST-4.2.3][LAB-012]Runtime Command Checking(Runtime指令檢查)", u"這個app沒有使用危險的function'Runtime.getRuntime().exec(\"...\")", ["Command"])

    # -------------------------------------------------------
    # [lab_029] - HTTPS ALLOW_ALL_HOSTNAME_VERIFIER checking: 
    # (1)inner class checking
    """
		Example Java code:
		    HttpsURLConnection.setDefaultHostnameVerifier(org.apache.http.conn.ssl.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);

		Example Bytecode code (The same bytecode for those two Java code):	
			(1)
			sget-object v11, Lorg/apache/http/conn/ssl/SSLSocketFactory;->ALLOW_ALL_HOSTNAME_VERIFIER:Lorg/apache/http/conn/ssl/X509HostnameVerifier;
	    	invoke-static {v11}, Ljavax/net/ssl/HttpsURLConnection;->setDefaultHostnameVerifier(Ljavax/net/ssl/HostnameVerifier;)V
	    	
	    	(2)
		   	new-instance v11, Lcom/example/androidsslconnecttofbtest/MainActivity$2;
		    invoke-direct {v11, p0}, Lcom/example/androidsslconnecttofbtest/MainActivity$2;-><init>(Lcom/example/androidsslconnecttofbtest/MainActivity;)V
		    invoke-static {v11}, Ljavax/net/ssl/HttpsURLConnection;->setDefaultHostnameVerifier(Ljavax/net/ssl/HostnameVerifier;)V

		Scenario:
			https://www.google.com/  => Google (SSL certificate is valid, CN: www.google.com)
			https://60.199.175.18   => IP of Google (SSL certificate is invalid, See Chrome error message.
	"""

    # First, find out who calls it
    path_HOSTNAME_INNER_VERIFIER = vmx.get_tainted_packages(
    ).search_class_methods_exact_match("Ljavax/net/ssl/HttpsURLConnection;",
                                       "setDefaultHostnameVerifier",
                                       "(Ljavax/net/ssl/HostnameVerifier;)V")
    path_HOSTNAME_INNER_VERIFIER2 = vmx.get_tainted_packages(
    ).search_class_methods_exact_match(
        "Lorg/apache/http/conn/ssl/SSLSocketFactory;", "setHostnameVerifier",
        "(Lorg/apache/http/conn/ssl/X509HostnameVerifier;)V")
    path_HOSTNAME_INNER_VERIFIER.extend(path_HOSTNAME_INNER_VERIFIER2)

    path_HOSTNAME_INNER_VERIFIER = filteringEngine.filter_list_of_paths(
        d, path_HOSTNAME_INNER_VERIFIER)

    dic_path_HOSTNAME_INNER_VERIFIER_new_instance = filteringEngine.get_class_container_dict_by_new_instance_classname_in_paths(
        d, analysis, path_HOSTNAME_INNER_VERIFIER, 1)  # parameter index 1

    # Second, find the called custom classes
    list_HOSTNAME_INNER_VERIFIER = []

    methods_hostnameverifier = get_method_ins_by_implement_interface_and_method(
        d, ["Ljavax/net/ssl/HostnameVerifier;"], TYPE_COMPARE_ANY, "verify",
        "(Ljava/lang/String; Ljavax/net/ssl/SSLSession;)Z")
    for method in methods_hostnameverifier:
        register_analyzer = analysis.RegisterAnalyzerVM_ImmediateValue(
            method.get_instructions())
        if register_analyzer.get_ins_return_boolean_value(
        ):  # Has security problem
            list_HOSTNAME_INNER_VERIFIER.append(method)

    list_HOSTNAME_INNER_VERIFIER = filteringEngine.filter_list_of_methods(
        list_HOSTNAME_INNER_VERIFIER)

    if list_HOSTNAME_INNER_VERIFIER:

        output_string = u""" 
這個app 允許 自定義的 HOSTNAME VERIFIER去接受所有的Common Names(CN)，這是一個很嚴重的漏洞會讓攻擊者使用他的有效證書進行中間人攻擊(MITM)
google doc:http://developer.android.com/training/articles/security-ssl.html 
OWASP Mobile Top 10 doc: https://www.owasp.org/index.php/Mobile_Top_10_2014-M3
看這本書內是如何解決的: http://goo.gl/BFb65r 
原網址
https://books.google.com.tw/books?id=DuC64OoJSGQC&pg=PA79&lpg=PA79&dq=Android+HostnameVerifier+verify+true&source=bl&ots=CaIs9KbmNx&sig=aNoyDFc4BKRwartdS_3wqCoWtlc&hl=zh-TW&sa=X&ei=tK8iU7_9DIqpkQWT3ICoAw#v=onepage&q=Android%20HostnameVerifier%20verify%20true&f=false

看看 Common Name(CN)認證的重要性.
使用google chrome做導航:
 - https://www.google.com   => SSL證書是有效的
 - https://60.199.175.158/  => 這是google.com的IP位置, 但CN是不符合的, 讓證書無效化你仍然可以進入google但你無法確定是否有中間人攻擊
"""
        output_string_en = u"""
This app allows the custom HOSTNAME VERIFIER to accept all Common Names (CN), which is a very serious vulnerability that would allow an attacker to use his valid certificate for a man-in-the-middle attack (MITM)
google doc:http://developer.android.com/training/articles/security-ssl.html 
OWASP Mobile Top 10 doc: https://www.owasp.org/index.php/Mobile_Top_10_2014-M3
See how it was solved in this book: http://goo.gl/BFb65r 
Original URL
https://books.google.com.tw/books?id=DuC64OoJSGQC&pg=PA79&lpg=PA79&dq=Android+HostnameVerifier+verify+true&source=bl&ots= CaIs9KbmNx&sig=aNoyDFc4BKRwartdS_3wqCoWtlc&hl=zh-TW&sa=X&ei=tK8iU7_9DIqpkQWT3ICoAw#v=onepage&q=Android%20HostnameVerifier%20verify 20verify%20true&f=false

See the importance of Common Name(CN) authentication.
Use google chrome to navigate:
 - https://www.google.com => SSL certificate is valid
 - https://60.199.175.158/ => This is the IP location of google.com, but the CN is not matched, so the certificate is invalidated and you can still access google but you can't be sure if there is a man-in-the-middle attack
"""
        writer.startWriter(
            "SSL_CN1", LEVEL_CRITICAL,
            u"[AS-lab029][OWASP-V6.3][MAST-4.2.6][工-4.1.4.2.3, 4.1.4.2.4, 4.1.5.1.2][M5] SSL 實作檢查 (在自定義的classes檢驗 Host Name)",
            output_string + "||" + output_string_en, ["SSL_Security"])

        for method in list_HOSTNAME_INNER_VERIFIER:
            writer.write(method.easy_print())

            # because one class may initialize by many new instances of it
            method_class_name = method.get_class_name()
            if method_class_name in dic_path_HOSTNAME_INNER_VERIFIER_new_instance:
                writer.show_Paths(
                    d, dic_path_HOSTNAME_INNER_VERIFIER_new_instance[
                        method_class_name])
    # else:
    #     writer.startWriter(
    #         "SSL_CN1", LEVEL_INFO,
    #         u"[AS-lab029][OWASP-V6.3][MAST-4.2.6][工4.1.4.2.3, 4.1.4.2.4, 4.1.5.1.2][M5] SSL 實作檢查 (在自定義的classes檢驗 Host Name)",
    #         "Self-defined HOSTNAME VERIFIER checking OK.", ["SSL_Security"])

    # -------------------------------------------------------
    # [lab_030] - HTTPS ALLOW_ALL_HOSTNAME_VERIFIER checking: 
    # (2)ALLOW_ALL_HOSTNAME_VERIFIER fields checking

    if "Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;" in dic_path_HOSTNAME_INNER_VERIFIER_new_instance:
        path_HOSTNAME_INNER_VERIFIER_new_instance = dic_path_HOSTNAME_INNER_VERIFIER_new_instance[
            "Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;"]
    else:
        path_HOSTNAME_INNER_VERIFIER_new_instance = None

    # "vmx.get_tainted_field" will return "None" if nothing found
    field_ALLOW_ALL_HOSTNAME_VERIFIER = vmx.get_tainted_field(
        "Lorg/apache/http/conn/ssl/SSLSocketFactory;",
        "ALLOW_ALL_HOSTNAME_VERIFIER",
        "Lorg/apache/http/conn/ssl/X509HostnameVerifier;")

    if field_ALLOW_ALL_HOSTNAME_VERIFIER:
        filtered_ALLOW_ALL_HOSTNAME_VERIFIER_paths = filteringEngine.filter_list_of_variables(
            d, field_ALLOW_ALL_HOSTNAME_VERIFIER.get_paths())
    else:
        filtered_ALLOW_ALL_HOSTNAME_VERIFIER_paths = None

    if path_HOSTNAME_INNER_VERIFIER_new_instance or filtered_ALLOW_ALL_HOSTNAME_VERIFIER_paths:

        output_string = u"""
這個app 沒有檢查Common Names(CN)的有效性，這是一個很嚴重的漏洞會讓攻擊者使用他的有效證書進行中間人攻擊(MITM)
google doc:http://developer.android.com/training/articles/security-ssl.html 
OWASP Mobile Top 10 doc: https://www.owasp.org/index.php/Mobile_Top_10_2014-M3
看這本書內是如何解決的: http://goo.gl/BFb65r 

看看 Common Name(CN)認證的重要性.
使用google chrome做導航:
 - https://www.google.com   => SSL證書是有效的
 - https://60.199.175.158/  => 這是google.com的IP位置, 但CN是不符合的, 讓證書無效化你仍然可以進入google但你無法確定是否有中間人攻擊
 請檢查下列的methods:"""

        output_string_en = """
This app does not check the validity of Common Names (CN), which is a very serious vulnerability that would allow an attacker to use his valid certificate for a man-in-the-middle attack (MITM)
google doc:http://developer.android.com/training/articles/security-ssl.html 
OWASP Mobile Top 10 doc: https://www.owasp.org/index.php/Mobile_Top_10_2014-M3
See how it is addressed in this book: http://goo.gl/BFb65r 

See the importance of Common Name(CN) authentication.
Use google chrome to navigate:
 - https://www.google.com => SSL certificate is valid
 - https://60.199.175.158/ => This is the IP location of google.com, but the CN is not matched, so the certificate is invalidated and you can still access google but you can't be sure if there is a man-in-the-middle attack
 Please check the following methods:
        """

        writer.startWriter(
            "SSL_CN2", LEVEL_CRITICAL,
            u"[AS-lab030][OWASP-V6.3][MAST-4.2.6][工-4.1.4.2.3, 4.1.4.2.4, 4.1.5.1.2][M5] SSL實作檢查(辨識Host Name)",
            output_string + "||" + output_string_en, ["SSL_Security"])

        if filtered_ALLOW_ALL_HOSTNAME_VERIFIER_paths:
            """
                    Example code: 
                    SSLSocketFactory factory = SSLSocketFactory.getSocketFactory();
                    factory.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
            """

            for path in filtered_ALLOW_ALL_HOSTNAME_VERIFIER_paths:
                writer.show_single_PathVariable(d, path)

        if path_HOSTNAME_INNER_VERIFIER_new_instance:
            """
                    Example code: 
                    SSLSocketFactory factory = SSLSocketFactory.getSocketFactory();
                    factory.setHostnameVerifier(new AllowAllHostnameVerifier());
            """
            # For this one, the exclusion procedure is done on earlier
            writer.show_Paths(d, path_HOSTNAME_INNER_VERIFIER_new_instance)
    # else:
    #     writer.startWriter(
    #         "SSL_CN2", LEVEL_INFO,
    #         u"[AS-lab030][OWASP-V6.3][MAST-4.2.6][工-4.1.4.2.3, 4.1.4.2.4, 4.1.5.1.2][M5] SSL實作檢查(辨識Host Name)",
    #         u"漏洞\"ALLOW_ALL_HOSTNAME_VERIFIER\" field 設定 或 \"AllowAllHostnameVerifier\" class instance 沒有發現.",
    #         ["SSL_Security"])

    # -------------------------------------------------------
    # [lab_031] - SSL getInsecure


    result = get_androguard('/lab031')
    path_getInsecure = result['results']
    # path_getInsecure = vmx.get_tainted_packages(
    # ).search_class_methods_exact_match(
    #     "Landroid/net/SSLCertificateSocketFactory;", "getInsecure",
    #     "(I Landroid/net/SSLSessionCache;)Ljavax/net/ssl/SSLSocketFactory;")
    # path_getInsecure = filteringEngine.filter_list_of_paths(
    #     d, path_getInsecure)

    if path_getInsecure:
        output_string = u"""Sockets使用這種factory(不安全的method "getInsecure")對於中間人攻擊是有弱點的，可以參考http://developer.android.com/reference/android/net/SSLCertificateSocketFactory.html#getInsecure(int, android.net.SSLSessionCache)，建議移除不安全的程式碼:"""
        output_string_en = u"""Sockets using this factory (insecure method "getInsecure") is weak against man-in-the-middle attacks, see http://developer.android.com/reference/android/net/ SSLCertificateSocketFactory.html#getInsecure(int, android.net.SSLSessionCache), it is recommended to remove the insecure code:"""

        writer.startWriter(
            "SSL_CN3", LEVEL_CRITICAL,
            u"[AS-lab031][OWASP-V1.3,V1.4,V5.1,V5.2][MAST-4.2.6][工4.1.5.1.1][M5] SSL實作檢查 (不安全的 component)",
            output_string + "||" + output_string_en, ["SSL_Security"])
        writer.write("Found!:")
        for i in path_getInsecure:
            writer.write( i['class_name'] + " " + i['method_name'])

            
        #writer.show_Paths(d, path_getInsecure)
    # else:
    #     writer.startWriter(
    #         "SSL_CN3", LEVEL_INFO,
    #         u"[AS-lab031][OWASP-V1.3,V1.4,V5.1,V5.2][MAST-4.2.6][工-4.1.5.1.2][M5] SSL實作檢查 (不安全的 component)",
    #         u"沒有偵測到使用不安全方法\"getInsecure\"的SSLSocketFactory.", ["SSL_Security"])

    # -------------------------------------------------------
    # [lab_032] - HttpHost default scheme "http"
    """
    這個檢測像會對PDF開啟會壞掉
	閱讀這篇論文以了解為何要設計這個vector:"The Most Dangerous Code in the World: Validating SSL Certificates in Non-Browser Software"
	
			Java code 範例:
	    	HttpHost target = new HttpHost(uri.getHost(), uri.getPort(), HttpHost.DEFAULT_SCHEME_NAME);

	    Smali code 範例:
	    	const-string v4, "http"
	    	invoke-direct {v0, v2, v3, v4}, Lorg/apache/http/HttpHost;-><init>(Ljava/lang/String; I Ljava/lang/String;)V
	"""

    list_HttpHost_scheme_http = []
    path_HttpHost_scheme_http = vmx.get_tainted_packages(
    ).search_class_methods_exact_match(
        "Lorg/apache/http/HttpHost;", "<init>",
        "(Ljava/lang/String; I Ljava/lang/String;)V")
    path_HttpHost_scheme_http = filteringEngine.filter_list_of_paths(
        d, path_HttpHost_scheme_http)
    for i in analysis.trace_Register_value_by_Param_in_source_Paths(
            d, path_HttpHost_scheme_http):
        if i.getResult()[3] is None:
            continue
        if (i.is_string(
                i.getResult()[3])) and ((i.getResult()[3]).lower() == "http"):
            list_HttpHost_scheme_http.append(i.getPath())

    if list_HttpHost_scheme_http:
        writer.startWriter(
            u"SSL_預設_SCHEME_NAME", LEVEL_CRITICAL,
            u"[AS-lab032][MAST-4.2.6][工-4.1.2.4.1][M5] SSL實作檢查(HttpHost)",
            u"這個app使用\"HTTPHost\",但預設的scheme是\"http\" 或者 \"HttpHost.DEFAULT_SCHEME_NAME(http)\.請改成\"https\":" + "||" + \
            u"This app uses \"HTTPHost\", but the default scheme is \"http\" or \"HttpHost.DEFAULT_SCHEME_NAME(http)\. Please change it to \"https\":", 
            ["SSL_Security"])

        for i in list_HttpHost_scheme_http:
            writer.show_Path(d, i)
    # else:
    #     writer.startWriter(u"SSL_預設_SCHEME_NAME", LEVEL_INFO,
    #                        u"[AS-lab032][MAST-4.2.6][工-4.1.2.4.1][M5] SSL實作檢查(HttpHost)",
    #                        u"HttpHost 預設_SCHEME_NAME  檢查: 正確",
    #                        ["SSL_Security"])

    # -------------------------------------------------------
    # [lab_033] - WebViewClient onReceivedSslError errors

    # First, find out who calls setWebViewClient
    path_webviewClient_new_instance = vmx.get_tainted_packages(
    ).search_class_methods_exact_match("Landroid/webkit/WebView;",
                                       "setWebViewClient",
                                       "(Landroid/webkit/WebViewClient;)V")
    dic_webviewClient_new_instance = filteringEngine.get_class_container_dict_by_new_instance_classname_in_paths(
        d, analysis, path_webviewClient_new_instance, 1)

    # Second, find which class and method extends it
    list_webviewClient = []
    methods_webviewClient = get_method_ins_by_superclass_and_method(
        d, ["Landroid/webkit/WebViewClient;"], "onReceivedSslError",
        "(Landroid/webkit/WebView; Landroid/webkit/SslErrorHandler; Landroid/net/http/SslError;)V"
    )
    for method in methods_webviewClient:
        if is_kind_string_in_ins_method(
                method, "Landroid/webkit/SslErrorHandler;->proceed()V"):
            list_webviewClient.append(method)

    list_webviewClient = filteringEngine.filter_list_of_methods(
        list_webviewClient)

    if list_webviewClient:
        writer.startWriter(
            "SSL_WEBVIEW", LEVEL_CRITICAL,
            u"[AS-lab033][OWASP-V6.5][MAST-4.2.6][工-4.1.4.2.4, 4.2.2.1.2][M3] SSL 實作檢查(WebViewClient for WebView)",
            u"""不要在有繼承"WebViewClient"的methods使用 "handler.proceed();" , 即使SSL證書是無效的他仍然可能會讓連線成立 (中間人攻擊漏洞).
相關文獻: 
(1)OWASP Mobile Top 10 doc: https://www.owasp.org/index.php/Mobile_Top_10_2014-M3
(2)https://jira.appcelerator.org/browse/TIMOB-4488
易受攻擊的codes:
""" + "||" + u"""Do not use "handler.proceed();" in methods that inherit from "WebViewClient", even if the SSL certificate is invalid it may still allow the connection to be established (man-in-the-middle attack vulnerability).
Related Documents: 
(1)OWASP Mobile Top 10 doc: https://www.owasp.org/index.php/Mobile_Top_10_2014-M3
(2)https://jira.appcelerator.org/browse/TIMOB-4488
Vulnerable Codes:""", ["SSL_Security"])

        for method in list_webviewClient:
            writer.write(method.easy_print())

            # because one class may initialize by many new instances of it
            method_class_name = method.get_class_name()
            if method_class_name in dic_webviewClient_new_instance:
                writer.show_Paths(
                    d, dic_webviewClient_new_instance[method_class_name])

    # else:
    #     writer.startWriter(
    #         "SSL_WEBVIEW", LEVEL_INFO,
    #         u"[AS-lab033][OWASP-V6.5][MAST-4.2.6][工-4.1.4.2.4, 4.2.2.1.2][M3] SSL實作檢查 (WebViewClient for WebView)",
    #         u"沒有察覺到 \"WebViewClient\"(可能遭到中間人攻擊)的漏洞.", ["SSL_Security"])

    # -------------------------------------------------------
    # [lab_034] - WebView security configuration audit (migrated to androguard_server)
    # 從「看到 JS enable 就標」進化為「真實危險配置才標」: 3 條規則
    result_lab034 = get_androguard('/lab_034')

    if result_lab034 and isinstance(result_lab034, dict) and result_lab034.get('has_finding'):
        verdict_034  = result_lab034.get('verdict', 'WARNING')
        critical_034 = result_lab034.get('critical', [])

        if verdict_034 == 'CRITICAL':
            level_034 = LEVEL_CRITICAL
        elif verdict_034 == 'WARNING':
            level_034 = LEVEL_WARNING
        else:
            level_034 = LEVEL_INFO

        writer.startWriter(
            "LAB_034_WEBVIEW_CONFIG", level_034,
            u"[AS-lab034][MAS-4.1.5.4.2][MASVS-PLATFORM-2][CWE-79] WebView 安全配置檢查",
            u"稽核 WebView 安全配置,聚焦三種真實風險: "
            u"CRITICAL (setAllowFileAccessFromFileURLs(true) -> JS 可讀本地檔案); "
            u"CRITICAL (setAllowUniversalAccessFromFileURLs(true) -> JS 繞 Same-Origin Policy); "
            u"WARNING (setJavaScriptEnabled(true) + loadUrl(變數) 同 method -> 可能載入不可信內容 XSS)。"
            u"單獨 setJavaScriptEnabled(true) 或 loadUrl(常數) 不報以避免噪音。"
            u" Ref: https://developer.android.com/reference/android/webkit/WebSettings"
            + "||" +
            u"Audits WebView security configuration. Focuses on three real WebView risks: "
            u"CRITICAL (setAllowFileAccessFromFileURLs(true) -> JS reads local files); "
            u"CRITICAL (setAllowUniversalAccessFromFileURLs(true) -> JS bypasses Same-Origin Policy); "
            u"WARNING (setJavaScriptEnabled(true) + loadUrl(variable) in same method -> XSS via untrusted URL). "
            u"setJavaScriptEnabled(true) alone or loadUrl(constant) alone are NOT reported to avoid noise."
            u" Ref: https://developer.android.com/reference/android/webkit/WebSettings",
            ["WebView", "XSS"])

        # Only output CRITICAL findings — keep report compact
        if critical_034:
            writer.write(u"[CRITICAL: %d]" % len(critical_034))
            for f in critical_034:
                cls = f.get('class', '')
                if cls.startswith('L') and cls.endswith(';'):
                    cls = cls[1:-1].replace('/', '.')
                writer.write(u"  %s.%s()  api=%s  reason=%s" % (
                    cls, f.get('method', ''), f.get('api', ''), f.get('reason', '')))

    # ------------------------------------------------------------------------
    # [lab_035] - Check Certificate Pinning:

    lab_035Response = get_androguard('/lab035')

    if lab_035Response and lab_035Response.get('has_finding') == True:
        print("lab_035 pass - Certificate Pinning implementation found")
    else:
        print("lab_035 DETECTED - Certificate Pinning is missing (security concern)")
        writer.startWriter(
            "CERTIFICATE_PINNING_MISSING", LEVEL_WARNING,
            u"[AS-lab035] Certificate Pinning 憑證固定缺失檢測 (靜態分析)",
            u"[靜態分析限制說明]\n" + \
            u"此分析結果基於靜態程式碼檢測,無法偵測以下情況:\n" + \
            u"- 程式碼混淆後的實作\n" + \
            u"- 動態載入的憑證固定邏輯\n" + \
            u"- 自訂或第三方框架的特殊實作方式\n" + \
            u"- Native code (JNI) 層級的實作\n" + \
            u"建議搭配動態分析 (如 Frida hook SSLContext/TrustManager) 進行驗證。\n\n" + \
            u"[檢測結果]\n" + \
            u"未偵測到常見的 Certificate Pinning 實作。缺少憑證固定可能使應用程式容易受到中間人攻擊 (Man-in-the-Middle Attack)。\n\n" + \
            u"[建議實作方式]\n" + \
            u"1. 使用 Network Security Config (Android 7.0+): 在 res/xml/ 目錄下建立 network_security_config.xml 並設定 <pin-set>\n" + \
            u"2. 使用程式碼實作: 如 OkHttp 的 CertificatePinner 或自訂 TrustManager\n\n" + \
            u"[參考資料]\n" + \
            u"- OWASP Mobile Security Testing Guide (MSTG-NETWORK-4)\n" + \
            u"- https://developer.android.com/training/articles/security-config\n" + \
            u" || " + \
            u"[Static Analysis Limitations]\n" + \
            u"This analysis is based on static code detection and cannot detect:\n" + \
            u"- Implementations hidden by code obfuscation\n" + \
            u"- Dynamically loaded certificate pinning logic\n" + \
            u"- Custom or third-party framework implementations\n" + \
            u"- Native code (JNI) level implementations\n" + \
            u"It is recommended to verify with dynamic analysis (e.g., Frida hooking SSLContext/TrustManager).\n\n" + \
            u"[Detection Result]\n" + \
            u"No common Certificate Pinning implementation detected. The absence of certificate pinning may make the application vulnerable to Man-in-the-Middle (MITM) attacks.\n\n" + \
            u"[Recommended Implementations]\n" + \
            u"1. Use Network Security Config (Android 7.0+): Create network_security_config.xml in res/xml/ and configure <pin-set>\n" + \
            u"2. Code-based implementation: Such as OkHttp's CertificatePinner or custom TrustManager\n\n" + \
            u"[References]\n" + \
            u"- OWASP Mobile Security Testing Guide (MSTG-NETWORK-4)\n" + \
            u"- https://developer.android.com/training/articles/security-config",
            ["CertificatePinning", "NetworkSecurity", "MITM-Risk", "StaticAnalysis"])
  
    # ------------------------------------------------------------------------
    # [lab_036] - Intent Redirection vulnerability detection

    result_intent_redirection = get_androguard('/lab036')

    if result_intent_redirection and isinstance(result_intent_redirection, dict):
        has_finding = result_intent_redirection.get('has_finding', False)
        results = result_intent_redirection.get('results', [])

        if has_finding:
            writer.startWriter(
                "INTENT_REDIRECTION", LEVEL_CRITICAL,
                u"[AS-lab036][OWASP-M1][CWE-927] Intent Redirection 意圖重定向漏洞",
                u"[靜態分析限制說明]\n"
                u"此結果為靜態分析偵測，存在誤報可能，建議人工進一步確認。\n"
                u"靜態分析無法判斷以下情況:\n"
                u"- getParcelableExtra() 取得的物件是否真的是 Intent\n"
                u"- 程式碼中是否已有隱含的驗證邏輯（如 try-catch、條件判斷）\n"
                u"- 混淆後的呼叫鏈是否已包含白名單過濾\n"
                u"建議搭配動態分析（如 Frida hook startActivity）進行驗證。\n\n"
                u"[偵測結果]\n"
                u"偵測到 Exported Activity 可能存在 Intent Redirection 漏洞。\n"
                u"該 Activity 接收外部傳入的 Intent，並可能直接使用該 Intent 啟動其他元件，未見明確的目標元件驗證。\n\n"
                u"漏洞說明:\n"
                u"1. Activity 設定為 exported=true，可被外部應用程式呼叫\n"
                u"2. 透過 getParcelableExtra() 取得外部傳入的 Intent 物件\n"
                u"3. 直接呼叫 startActivity()/startService()/sendBroadcast()，未見驗證目標元件\n\n"
                u"攻擊情境:\n"
                u"若確認無驗證，攻擊者可傳入惡意 Intent，啟動應用程式的私有 Activity，繞過存取控制，"
                u"或存取不應對外公開的功能。\n\n"
                u"修復建議:\n"
                u"- 驗證 Intent 的目標元件是否在允許清單中\n"
                u"- 避免直接轉發外部傳入的 Intent\n"
                u"- 改用明確的參數傳遞，由應用程式自行決定跳轉目標\n\n"
                u"參考資料:\n"
                u"https://developer.android.com/privacy-and-security/risks/intent-redirection?hl=zh-tw \n"
                + "||" +
                u"[Static Analysis Limitations]\n"
                u"This result is from static analysis and may contain false positives. Manual review is recommended.\n"
                u"Static analysis cannot determine:\n"
                u"- Whether the object from getParcelableExtra() is actually used as an Intent\n"
                u"- Whether implicit validation logic exists (e.g., try-catch, conditional checks)\n"
                u"- Whether obfuscated call chains already include allowlist filtering\n"
                u"It is recommended to verify with dynamic analysis (e.g., Frida hook on startActivity).\n\n"
                u"[Detection Result]\n"
                u"Potential Intent Redirection vulnerability detected in an exported Activity.\n"
                u"The Activity receives an externally supplied Intent and may directly use it to launch components "
                u"without explicit target component validation.\n\n"
                u"Vulnerability Details:\n"
                u"1. Activity is set as exported=true, accessible by external applications\n"
                u"2. Retrieves Intent object from external input via getParcelableExtra()\n"
                u"3. Calls startActivity()/startService()/sendBroadcast() without evident target validation\n\n"
                u"Attack Scenario:\n"
                u"If no validation is confirmed, an attacker can pass a malicious Intent to launch private Activities, "
                u"bypass access controls, or access functionality not intended for external use.\n\n"
                u"Remediation:\n"
                u"- Validate that the Intent's target component is in an allowlist\n"
                u"- Avoid directly forwarding externally received Intents\n"
                u"- Use explicit parameter passing and let the application decide the navigation target\n\n"
                u"References:\n"
                u"- https://developer.android.com/privacy-and-security/risks/intent-redirection?hl=zh-tw",
                ["Hacker", "Implicit_Intent"])

            for result_item in results:
                writer.write(u"\n[" + result_item.get('severity', 'UNKNOWN') + u"] " + result_item.get('issue', ''))
                if 'affected_methods' in result_item:
                    writer.write(u"Affected methods:")
                    for method_info in result_item['affected_methods']:
                        dangerous = u", ".join(method_info.get('dangerous_methods', []))
                        writer.write(u"  " + method_info['class'] + u"->" + method_info['method'] +
                                     (u"  [Dangerous call: " + dangerous + u"]" if dangerous else u""))

    # ------------------------------------------------------------------------
    # [lab_037] - Get a list of 'PathP' objects that are vulnerabilities
    """
		MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE checking:

		MODE_WORLD_READABLE = 1
		MODE_WORLD_WRITEABLE = 2
		MODE_WORLD_READABLE + MODE_WORLD_WRITEABLE = 3

		http://jimmy319.blogspot.tw/2011/07/android-internal-storagefile-io.html

		Example Java Code:
			FileOutputStream outputStream = openFileOutput("Hello_World", Activity.MODE_WORLD_READABLE);

		Example Smali Code:
			const-string v3, "Hello_World"
			const/4 v4, 0x1
		    invoke-virtual {p0, v3, v4}, Lcom/example/android_mode_world_testing/MainActivity;->openFileOutput(Ljava/lang/String;I)Ljava/io/FileOutputStream;
	"""
    list_path_openOrCreateDatabase = []
    list_path_openOrCreateDatabase2 = []
    list_path_getDir = []
    list_path_getSharedPreferences = []
    list_path_openFileOutput = []

    path_openOrCreateDatabase = vmx.get_tainted_packages(
    ).search_methods_exact_match(
        "openOrCreateDatabase",
        "(Ljava/lang/String; I Landroid/database/sqlite/SQLiteDatabase$CursorFactory;)Landroid/database/sqlite/SQLiteDatabase;"
    )
    path_openOrCreateDatabase = filteringEngine.filter_list_of_paths(
        d, path_openOrCreateDatabase)
    for i in analysis.trace_Register_value_by_Param_in_source_Paths(
            d, path_openOrCreateDatabase):
        if (0x1 <= i.getResult()[2] <= 0x3):
            list_path_openOrCreateDatabase.append(i.getPath())

    path_openOrCreateDatabase2 = vmx.get_tainted_packages(
    ).search_methods_exact_match(
        "openOrCreateDatabase",
        "(Ljava/lang/String; I Landroid/database/sqlite/SQLiteDatabase$CursorFactory; Landroid/database/DatabaseErrorHandler;)Landroid/database/sqlite/SQLiteDatabase;"
    )
    path_openOrCreateDatabase2 = filteringEngine.filter_list_of_paths(
        d, path_openOrCreateDatabase2)
    for i in analysis.trace_Register_value_by_Param_in_source_Paths(
            d, path_openOrCreateDatabase2):
        if (0x1 <= i.getResult()[2] <= 0x3):
            list_path_openOrCreateDatabase2.append(i.getPath())

    path_getDir = vmx.get_tainted_packages().search_methods_exact_match(
        "getDir", "(Ljava/lang/String; I)Ljava/io/File;")
    path_getDir = filteringEngine.filter_list_of_paths(d, path_getDir)
    for i in analysis.trace_Register_value_by_Param_in_source_Paths(
            d, path_getDir):
        if (0x1 <= i.getResult()[2] <= 0x3):
            list_path_getDir.append(i.getPath())

    path_getSharedPreferences = vmx.get_tainted_packages(
    ).search_methods_exact_match(
        "getSharedPreferences",
        "(Ljava/lang/String; I)Landroid/content/SharedPreferences;")
    path_getSharedPreferences = filteringEngine.filter_list_of_paths(
        d, path_getSharedPreferences)
    for i in analysis.trace_Register_value_by_Param_in_source_Paths(
            d, path_getSharedPreferences):
        if (0x1 <= i.getResult()[2] <= 0x3):
            list_path_getSharedPreferences.append(i.getPath())

    path_openFileOutput = vmx.get_tainted_packages(
    ).search_methods_exact_match(
        "openFileOutput", "(Ljava/lang/String; I)Ljava/io/FileOutputStream;")
    path_openFileOutput = filteringEngine.filter_list_of_paths(
        d, path_openFileOutput)
    for i in analysis.trace_Register_value_by_Param_in_source_Paths(
            d, path_openFileOutput):
        if (0x1 <= i.getResult()[2] <= 0x3):
            list_path_openFileOutput.append(i.getPath())

    if list_path_openOrCreateDatabase or list_path_openOrCreateDatabase2 or list_path_getDir or list_path_getSharedPreferences or list_path_openFileOutput:

        writer.startWriter(
            "MODE_WORLD_READABLE_OR_MODE_WORLD_WRITEABLE", LEVEL_CRITICAL,
            u"[AS-lab037][OWASP-V2.2,V2.8][MAST-4.2.7][工-4.1.2.5.3][M4] APP sandbox權限檢查",
            u"發現\"MODE_WORLD_READABLE\" or \"MODE_WORLD_WRITEABLE\" 安全問題 (請檢視: https://www.owasp.org/index.php/Mobile_Top_10_2014-M2):" + "||" + \
            u"\"MODE_WORLD_READABLE\" or \"MODE_WORLD_WRITEABLE\" security problem found (please check: https://www.owasp.org/index.php/Mobile_Top_10_2014-M2):"   
        )

        if list_path_openOrCreateDatabase:
            writer.write("[openOrCreateDatabase - 3 params]")
            for i in list_path_openOrCreateDatabase:
                writer.show_Path(d, i)
            writer.write("--------------------------------------------------")
        if list_path_openOrCreateDatabase2:
            writer.write("[openOrCreateDatabase - 4 params]")
            for i in list_path_openOrCreateDatabase2:
                writer.show_Path(d, i)
            writer.write("--------------------------------------------------")
        if list_path_getDir:
            writer.write("[getDir]")
            for i in list_path_getDir:
                writer.show_Path(d, i)
            writer.write("--------------------------------------------------")
        if list_path_getSharedPreferences:
            writer.write("[getSharedPreferences]")
            for i in list_path_getSharedPreferences:
                writer.show_Path(d, i)
            writer.write("--------------------------------------------------")
        if list_path_openFileOutput:
            writer.write("[openFileOutput]")
            for i in list_path_openFileOutput:
                writer.show_Path(d, i)
            writer.write("--------------------------------------------------")

    # else:
    #     writer.startWriter(
    #         "MODE_WORLD_READABLE_OR_MODE_WORLD_WRITEABLE", LEVEL_INFO,
    #         u"[AS-lab037][OWASP-V2.2,V2.8][MAST-4.2.7][工-4.1.2.5.3][M4] APP sandbox權限檢查",
    #         u"沒有\"MODE_WORLD_READABLE\" or \"MODE_WORLD_WRITEABLE\" 被發現在'openOrCreateDatabase' or 'openOrCreateDatabase2' or 'getDir' or 'getSharedPreferences' or 'openFileOutput'中"
    #     )

    # ------------------------------------------------------------------------
    # [lab_038] - List all native method
    """
		Example:
	    	const-string v0, "AndroBugsNdk"
	    	invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
	"""

    

    cm = d.get_class_manager()

    dic_NDK_library_classname_to_ndkso_mapping = {}
    list_NDK_library_classname_to_ndkso_mapping = []
    path_NDK_library_classname_to_ndkso_mapping = vmx.get_tainted_packages(
    ).search_class_methods_exact_match("Ljava/lang/System;", "loadLibrary",
                                       "(Ljava/lang/String;)V")
    path_NDK_library_classname_to_ndkso_mapping = filteringEngine.filter_list_of_paths(
        d, path_NDK_library_classname_to_ndkso_mapping)
    for i in analysis.trace_Register_value_by_Param_in_source_Paths(
            d, path_NDK_library_classname_to_ndkso_mapping):
        if (i.getResult()[0] is None) or (not i.is_string(0)):
            continue
        so_file_name = i.getResult()[0]
        src_class_name, src_method_name, src_descriptor = i.getPath().get_src(
            cm)
        if src_class_name is None:
            continue
        if src_class_name not in dic_NDK_library_classname_to_ndkso_mapping:
            dic_NDK_library_classname_to_ndkso_mapping[src_class_name] = []

        dic_NDK_library_classname_to_ndkso_mapping[src_class_name].append(
            toNdkFileFormat(str(i.getResult()[0])))
        list_NDK_library_classname_to_ndkso_mapping.append(
            [toNdkFileFormat(str(i.getResult()[0])),
             i.getPath()])

    list_NDK_library_classname_to_ndkso_mapping2 = []
    result = get_androguard('/lab038')
    list_NDK_library_classname_to_ndkso_mapping2 = result['results']
    if list_NDK_library_classname_to_ndkso_mapping2:
        writer.startWriter("NATIVE_LIBS_LOADING", LEVEL_NOTICE,
                           u"[AS-lab038][MAST-4.2.5] 原生函式庫載入程式碼檢查",
                           u"發現有載入原生的函式庫程式碼(System.loadLibrary(...)):" + "||" + u"Found native library code loaded (System.loadLibrary(...)) :")
        writer.write("Found!:")
        for i in list_NDK_library_classname_to_ndkso_mapping2:
            writer.write(i['class_name'] + " loadLibrary")
            #writer.show_Path(d, path)
    # else:
    #     writer.startWriter("NATIVE_LIBS_LOADING", LEVEL_INFO,
    #                        u"[AS-lab038][MAST-4.2.5][LAB-014] 原生函式庫載入程式碼檢查",
    #                        u"沒有發現載入原生的函式庫")

    dic_native_methods = {}
    regexp_sqlcipher_database_class = re.compile(".*/SQLiteDatabase;")
    for method in d.get_methods():
        if method.is_native():
            class_name = method.get_class_name()
            if filteringEngine.is_class_name_not_in_exclusion(class_name):
                if class_name not in dic_native_methods:
                    dic_native_methods[class_name] = []
                dic_native_methods[class_name].append(method)

            # <<Essential_Block_1>>
            if regexp_sqlcipher_database_class.match(class_name):
                # Make it to 2 conditions to add efficiency
                if (method.get_name() == "dbopen") or (
                        method.get_name() == "dbclose"):
                    isUsingSQLCipher = True  # This is for later use

    if dic_native_methods:
        if args.extra == 2:  # The output may be too verbose, so make it an option
            dic_native_methods_sorted = collections.OrderedDict(
                sorted(dic_native_methods.items()))

            writer.startWriter(
                "NATIVE_METHODS", LEVEL_NOTICE,
                u"[AS-lab038][OWASP-V1.1][MAST-4.2.5] Native Methods 檢查",
                u"發現原生的methods:" + "||" + u"Discover the native methods:")

            for class_name, method_names in dic_native_methods_sorted.items():
                if class_name in dic_NDK_library_classname_to_ndkso_mapping:
                    writer.write(
                        "Class: %s (Loaded NDK files: %s)" %
                        (class_name,
                         dic_NDK_library_classname_to_ndkso_mapping[class_name]
                         ))
                else:
                    writer.write("Class: %s" % (class_name))
                writer.write("   ->Methods:")
                for method in method_names:
                    writer.write("        %s%s" % (method.get_name(),
                                                   method.get_descriptor()))

    # else:
    #     if args.extra == 2:  # The output may be too verbose, so make it an option
    #         writer.startWriter(
    #             "NATIVE_METHODS", LEVEL_INFO,
    #             u"[AS-lab038][OWASP-V1.1][MAST-4.2.5][LAB-014]Native Methods 檢查",
    #             u"沒有發現原生的method")

    # ------------------------------------------------------------------------
    # [lab_042] - Unified Packer Detection
    # (replaces lab_039 Bangcle + lab_040 iJiami + lab_042 DexClassLoader)
    # Note: MonoDroid (lab_041) removed — it's a cross-platform framework, not a packer

    result_042 = get_androguard('/lab_042')
    if result_042 and isinstance(result_042, dict):
        packers_042    = result_042.get('packers', [])
        frameworks_042 = result_042.get('frameworks', [])

        # --- 加殼/框架報告（統一使用 AS-lab042 tag）---
        if packers_042:
            packer_names = ', '.join(p.get('name', '') for p in packers_042)
            writer.startWriter(
                "PACKER_DETECTION", LEVEL_NOTICE,
                u"[AS-lab042][MAST-5.2.5] 加殼/框架偵測 - %s" % packer_names,
                u"偵測到加殼框架，靜態分析結果可能不完整，建議提供未加殼的 APK 以利完整檢測:"
                + "||"
                + u"Packer detected. Static analysis results may be incomplete. Please provide the unpacked APK for full analysis:",
                ["Framework"])
            for packer in packers_042:
                pname = packer.get('name', '')
                evidence = ', '.join(packer.get('evidence', []))
                writer.write(u"  [%s]  evidence: %s" % (pname, evidence))

    # ------------------------------------------------------------------------
    # [lab_043] - Get External Storage Directory access invoke

    paths_ExternalStorageAccess = vmx.get_tainted_packages(
    ).search_class_methods_exact_match("Landroid/os/Environment;",
                                       "getExternalStorageDirectory",
                                       "()Ljava/io/File;")
    paths_ExternalStorageAccess = filteringEngine.filter_list_of_paths(
        d, paths_ExternalStorageAccess)
    if paths_ExternalStorageAccess:
        writer.startWriter(
            u"外部空間儲存", LEVEL_WARNING,
            u"[AS-lab043][OWASP-V2.1,V2.5,V2.6,V2.10][MAST-4.2.7][工-4.1.2.3.7] 外部空間儲存",
            u"發現在外部空間儲存檔案 (記得不要將重要檔案存在外部空間):" + "||" + u"You will find files stored in external space (remember not to store important files in external space):")
        writer.show_Paths(d, paths_ExternalStorageAccess)
    # else:
    #     writer.startWriter(
    #         u"外部空間儲存", LEVEL_INFO,
    #         u"[AS-lab043][OWASP-V2.1,V2.5,V2.6,V2.10][MAST-4.2.7][工-4.1.2.3.7] 外部空間儲存",
    #         u"未發現外部空間儲存")

    # ------------------------------------------------------------------------
    # [lab_044] - Dirty Steam Attack Detection

    result_dirty_steam = get_androguard('/lab_044')

    if result_dirty_steam and isinstance(result_dirty_steam, dict):
        has_finding = result_dirty_steam.get('has_finding', False)
        vulnerable_activities = result_dirty_steam.get('vulnerable_activities', [])
        results = result_dirty_steam.get('results', [])

        if has_finding:
            writer.startWriter(
                "DIRTY_STEAM", LEVEL_CRITICAL,
                u"[AS-lab044][OWASP-M7][CWE-73] Dirty Steam 路徑穿越攻擊漏洞",
                u"發現潛在 Dirty Steam 攻擊漏洞! 應用程式接收外部檔案但未驗證檔案名稱，攻擊者可使用路徑穿越 (../) 寫入任意位置的檔案。\n\n"
                u"漏洞說明:\n"
                u"1. 應用程式透過 ACTION_SEND/SEND_MULTIPLE 接收來自其他 app 的檔案\n"
                u"2. 使用 ContentResolver.query() 查詢 _display_name 但未驗證\n"
                u"3. 直接使用檔案名稱建立本地檔案，可能導致路徑穿越攻擊\n\n"
                u"修復建議:\n"
                u"- 移除路徑分隔符號: filename.replaceAll(\"[/\\\\\\\\]\", \"\")\n"
                u"- 移除路徑穿越字元: filename.replaceAll(\"\\\\.\\\\.\", \"\")\n"
                u"- 只使用檔案名稱: new File(filename).getName()\n\n"
                u"參考資料:\n"
                u"- https://i.blackhat.com/Asia-23/AS-23-Valsamaras-Dirty-Stream-Attack-Turning-Android.pdf\n"
                u"- https://cwe.mitre.org/data/definitions/73.html"
                + "||" +
                u"Dirty Steam attack vulnerability detected! The application receives external files without validating filenames. Attackers can use path traversal (../) to write files to arbitrary locations.\n\n"
                u"Vulnerability Details:\n"
                u"1. Application receives files from other apps via ACTION_SEND/SEND_MULTIPLE\n"
                u"2. Uses ContentResolver.query() to get _display_name without validation\n"
                u"3. Directly uses filename for local file operations, allowing path traversal attacks\n\n"
                u"Remediation:\n"
                u"- Remove path separators: filename.replaceAll(\"[/\\\\\\\\]\", \"\")\n"
                u"- Remove path traversal: filename.replaceAll(\"\\\\.\\\\.\", \"\")\n"
                u"- Use basename only: new File(filename).getName()\n\n"
                u"References:\n"
                u"- https://i.blackhat.com/Asia-23/AS-23-Valsamaras-Dirty-Stream-Attack-Turning-Android.pdf\n"
                u"- https://cwe.mitre.org/data/definitions/73.html",
                ["Hacker", "SSL_Security"])

            # Show vulnerable activities that accept external files
            if vulnerable_activities:
                writer.write("\n接收外部檔案的 Activity (ACTION_SEND/SEND_MULTIPLE):")
                writer.write("Activities receiving external files (ACTION_SEND/SEND_MULTIPLE):")
                for activity_info in vulnerable_activities:
                    writer.write("  - " + activity_info['activity'] + " (" + activity_info['action'] + ")")

            # Show detailed analysis results
            for result_item in results:
                writer.write("\n[" + result_item.get('severity', 'UNKNOWN') + "] " + result_item.get('issue', ''))
                writer.write(result_item.get('description', ''))

                if 'recommendation' in result_item:
                    writer.write("建議 (Recommendation): " + result_item['recommendation'])

                if 'affected_methods' in result_item:
                    writer.write("\n受影響的方法 (Affected methods):")
                    for method_info in result_item['affected_methods']:
                        writer.write("  " + method_info['class'] + "->" + method_info['method'])
                        if method_info.get('has_file_operation'):
                            writer.write("    [!] 包含檔案操作 (Contains file operations)")

        elif vulnerable_activities:
            # Has ACTION_SEND but no ContentResolver usage detected
            writer.startWriter(
                "DIRTY_STEAM", LEVEL_NOTICE,
                u"[AS-lab044][OWASP-M7][CWE-73] Dirty Steam 潛在風險檢測",
                u"應用程式接收外部檔案 (ACTION_SEND/SEND_MULTIPLE)，但未檢測到使用 ContentResolver 查詢檔案名稱。\n"
                u"建議檢查: 如果處理外部檔案，請確保驗證檔案名稱。"
                + "||" +
                u"Application receives external files (ACTION_SEND/SEND_MULTIPLE), but no ContentResolver usage detected.\n"
                u"Recommendation: If handling external files, ensure filename validation.",
                ["Hacker", "SSL_Security"])

            writer.write("\n接收外部檔案的 Activity:")
            for activity_info in vulnerable_activities:
                writer.write("  - " + activity_info['activity'] + " (" + activity_info['action'] + ")")

    # ------------------------------------------------------------------------
    # [lab_045] - Find all "dangerous" permission
    """
		android:permission
		android:readPermission (for ContentProvider)
		android:writePermission (for ContentProvider)
	"""

    # Get a mapping dictionary
    PermissionName_to_ProtectionLevel = a.get_PermissionName_to_ProtectionLevel_mapping(
    )

    dangerous_custom_permissions = []
    for name, protectionLevel in PermissionName_to_ProtectionLevel.items():
        if protectionLevel == PROTECTION_DANGEROUS:  # 1:"dangerous"
            dangerous_custom_permissions.append(name)

    if dangerous_custom_permissions:
        writer.startWriter(
            "PERMISSION_DANGEROUS", LEVEL_CRITICAL,
            u"[AS-lab045][OWASP-V6.1][MAST-4.2.1][工-4.1.2.5.3] AndroidManifest ProtectionLevel為dangerous 的權限檢查",
            u"""上述的class的保護等級(ProtectionLevel)是Dangerous, 讓其他app可以存取此權限 (AndroidManifest.xml). 
這個app應該宣告權限為 "android:protectionLevel" of "signature" 或者"signatureOrSystem" 讓其他app不能從此app註冊及接收訊息. 
宣告android:protectionLevel="signature" 讓其他app需要有相通的證書簽名才能夠存取此app. 
請改變下列權限:"""+ "||" + \
u"""The ProtectionLevel of the above class is Dangerous, so that other apps can access this permission (AndroidManifest.xml). 
This app should declare the permission as "android:protectionLevel" of "signature" or "signatureOrSystem" so that other apps cannot register and receive messages from this app. 
Declare android:protectionLevel="signature" so that other apps need to have the same certificate signature to access this app. 
Please change the following permissions:
""")

        for class_name in dangerous_custom_permissions:
            writer.write(class_name)

            who_use_this_permission = get_all_components_by_permission(
                a.get_AndroidManifest(), class_name)
            who_use_this_permission = collections.OrderedDict(
                sorted(who_use_this_permission.items()))
            if who_use_this_permission:
                for key, valuelist in who_use_this_permission.items():
                    for list_item in valuelist:
                        writer.write("    -> used by (" + key + ") " +
                                     a.format_value(list_item))
    # else:
    #     writer.startWriter(
    #         "PERMISSION_DANGEROUS", LEVEL_INFO,
    #         u"[AS-lab045][OWASP-V6.1][MAST-4.2.1][工-4.1.2.5.3] AndroidManifest ProtectionLevel 為 dangerous 的權限檢查",
    #         u"沒有發現 \"dangerous\"protection level 的權限(AndroidManifest.xml).")

    # ------------------------------------------------------------------------
    # [lab_046] - Find all "normal" or default permission

    normal_or_default_custom_permissions = []
    for name, protectionLevel in PermissionName_to_ProtectionLevel.items():
        if protectionLevel == PROTECTION_NORMAL:  # 0:"normal" or not set
            normal_or_default_custom_permissions.append(name)

    if normal_or_default_custom_permissions:
        writer.startWriter(
            "PERMISSION_NORMAL", LEVEL_WARNING,
            "[AS-lab046][OWASP-V6.1][MAST-4.2.1][工-4.1.2.5.3] AndroidManifest Normal ProtectionLevel of Permission Checking",
            u"""上述的class的保護等級(ProtectionLevel)是Dangerous, 讓其他app可以存取此權限 (AndroidManifest.xml). 
這個app應該宣告權限為 "android:protectionLevel" of "signature" 或者"signatureOrSystem" 讓其他app不能從此app註冊及接收訊息. 
宣告android:protectionLevel="signature" 讓其他app需要有相通的證書簽名才能夠存取此app. 
請改變下列權限:""" + "||" + \
u"""The ProtectionLevel of the above class is Dangerous, so that other apps can access this permission (AndroidManifest.xml). 
This app should declare the permission as "android:protectionLevel" of "signature" or "signatureOrSystem" so that other apps cannot register and receive messages from this app. 
Declare android:protectionLevel="signature" so that other apps need to have the same certificate signature to access this app. 
Please change the following permissions:
""")
        for class_name in normal_or_default_custom_permissions:
            writer.write(class_name)
            who_use_this_permission = get_all_components_by_permission(
                a.get_AndroidManifest(), class_name)
            who_use_this_permission = collections.OrderedDict(
                sorted(who_use_this_permission.items()))
            if who_use_this_permission:
                for key, valuelist in who_use_this_permission.items():
                    for list_item in valuelist:
                        writer.write("    -> used by (" + key + ") " +
                                     a.format_value(list_item))
    # else:
    #     writer.startWriter(
    #         "PERMISSION_NORMAL", LEVEL_INFO,
    #         u"[OWASP-V6.1][MAST-4.2.1][工-4.1.2.5.3]AndroidManifest ProtectionLevel為normal 的權限檢查",
    #         u"沒有發現 \"normal\"或\"default\"protection level 的權限(AndroidManifest.xml)."
    #     )

    # ------------------------------------------------------------------------
    # [lab_047] - Lost "android:" prefix in exported components

    list_lost_exported_components = []
    find_tags = [
        "activity", "activity-alias", "service", "receiver", "provider"
    ]
    xml = a.get_AndroidManifest()
    for tag in find_tags:
        for item in xml.getElementsByTagName(tag):
            name = item.getAttribute("android:name")
            exported = item.getAttribute("exported")
            if (not isNullOrEmptyString(name)) and (
                    not isNullOrEmptyString(exported)):
                list_lost_exported_components.append((tag, name))

    if list_lost_exported_components:
        writer.startWriter(
            "PERMISSION_NO_PREFIX_EXPORTED", LEVEL_CRITICAL,
            u"[AS-lab047][OWASP-V1.5,V6.4][工-4.1.2.5.3, 4.1.5.1.1][CVE-2013-6272][M4] AndroidManifest Exported Lost Prefix 檢查",
            u"""找到exported components 忘記在最前面加"android:" (AndroidManifest.xml). 
  相關的資料 : (1)http://blog.curesec.com/article/blog/35.html               
               (2)http://blogs.360.cn/360mobile/2014/07/08/cve-2013-6272/""" + "||" + \
            u"""Find the exported components Forget to add "android:" (AndroidManifest.xml) at first. 
  Related information : (1)http://blog.curesec.com/article/blog/35.html               
               (2)http://blogs.360.cn/360mobile/2014/07/08/cve-2013-6272/""",
            None, "CVE-2013-6272")

        for tag, name in list_lost_exported_components:
            writer.write(("%10s => %s") % (tag, a.format_value(name)))

    # else:
    #     writer.startWriter(
    #         "PERMISSION_NO_PREFIX_EXPORTED", LEVEL_INFO,
    #         u"[AS-lab047][OWASP-V1.5,V6.4][工-4.1.2.5.3, 4.1.5.1.1][CVE-2013-6272][M4] AndroidManifest Exported Lost Prefix 檢查",
    #         u"沒有exported components 忘記在前面加\"android:\" ", None,
    #         "CVE-2013-6272")

    # ------------------------------------------------------------------------
    # [lab_048] - "exported" checking (activity, activity-alias, service, receiver):
    """
		Remember: Even if the componenet is protected by "signature" level protection,
		it still cannot receive the broadcasts from other apps if the component is set to [exported="false"].
	    ---------------------------------------------------------------------------------------------------

		Even if the component is exported, it still can be protected by the "android:permission", for example:
		
	    <permission
	        android:name="com.example.androidpermissionexported.PermissionControl"
	        android:protectionLevel="signature" >
	    </permission>
	    <receiver
	        android:name=".SimpleBroadcastReceiver"
	        android:exported="true"
	        android:permission="com.example.androidpermissionexported.PermissionControl" >
	        <intent-filter>
	            <action android:name="com.example.androidpermissionexported.PermissionTest" />
	            <category android:name="android.intent.category.DEFAULT" />
	        </intent-filter>
	    </receiver>

		Apps with the same signature(signed with the same certificate) can send and receive the broadcasts with each other.
		Conversely, apps that do not have the same signature cannot send and receive the broadcasts with each other.
		If the protectionLevel is "normal" or not set, then the sending and receiving of broadcasts are not restricted.
		
		Even if the Action is used by the app itself, it can still be initialized from external(3rd-party) apps 
		if the [exported="false"] is not specified, for example:
	    Intent intent = new Intent("net.emome.hamiapps.am.action.UPDATE_AM");
	    intent.setClassName("net.emome.hamiapps.am", "net.emome.hamiapps.am.update.UpdateAMActivity");
	    startActivity(intent);

	    ---------------------------------------------------------------------------------------

	    **[PERMISSION_CHECK_STAGE]:
	        (1)If android:permission not set => Warn it can be accessed from external
	        (2)If android:permission is set => 
	            Check its corresponding android:protectionLevel is "not set(default: normal)" or "normal" or "dangerous"=> Warn it can be accessed from external
	            If the corresponding permission tag is not found => Ignore

	            **If the names of all the Action(s) are prefixing with "com.android." or "android." =>  Notify with a low priority warning
	                <receiver android:name="jp.naver.common.android.billing.google.checkout.BillingReceiver">
	                    <intent-filter>
	                        <action android:name="com.android.vending.billing.IN_APP_NOTIFY" />
	                        <action android:name="com.android.vending.billing.RESPONSE_CODE" />
	                        <action android:name="com.android.vending.billing.PURCHASE_STATE_CHANGED" />
	                    </intent-filter>
	                </receiver>
	            **You need to consider the Multiple Intent, for example:
	                <receiver android:name=".service.push.SystemBroadcastReceiver">
	                    <intent-filter android:enabled="true" android:exported="false">
	                        <action android:name="android.intent.action.BOOT_COMPLETED" />
	                        <action android:name="android.net.conn.CONNECTIVITY_CHANGE" />
	                    </intent-filter>
	                    <intent-filter android:enabled="true" android:exported="false">
	                        <action android:name="android.intent.action.PACKAGE_REPLACED" />
	                        <data android:scheme="package" android:path="jp.naver.line.android" />
	                    </intent-filter>
	                </receiver>
	            **The preceding example: intent-filter is set incorrectly. intent-filter does not have the "android:exported" => Warn misconfiguration


	    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	    [REASON_REGION_1]
	    **If exported is not set, the protectionalLevel of android:permission is set to "normal" by default =>
	        1.It "cannot" be accessed by other apps on Android 4.2 devices 
	        2.It "can" be accessed by other apps on Android 4.1 devices 

	    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
	    If it is receiver, service, activity or activity-alias, check if the exported is set:
	        exported="false" => No problem

	        exported="true" => Go to [PERMISSION_CHECK_STAGE]

	        exported is not set => 
	            If it has any intent-filter:
	                Yes => Go to [PERMISSION_CHECK_STAGE]
	                No  => If the intent-filter is not existed, it is exported="false" by default => X(Ignore)

	        **Main Problem: If it is still necessary to check the setting of "android:permission"


	    If it is provider, the intent-filter must not exist, so check if the exported is set:
	        ->[exported="true"] or [exported is not set] :

	            =>1.If [exported is not set] + [android:targetSdkVersion >= 17], add to the Warning List. Check the reason: [REASON_REGION_1]
	                It is suggested to add "exported" and tell the users that the default value is not the same among different platforms
	                => Check Google's document (The default value is "true" for applications that set either android:minSdkVersion or android:targetSdkVersion to "16" or lower. 
						For applications that set either of these attributes to "17" or higher, the default is "false". - http://developer.android.com/guide/topics/manifest/provider-element.html#exported)

	            =>2.[PERMISSION_CHECK_STAGE, and check "android:readPermission" and "android:writePermission", and check android:permission, android:writePermission, android:readPermission]
						=> If any of the corresponding setting for protectionLevel is not found ,then ignore it.
						   If any of the corresponding setting for protectionLevel is found, warn the users when the protectionLevel is "dangerous" or "normal".

	        ->exported="false": 
	            => X(Ignore)
	"""

    list_ready_to_check = []
    find_tags = ["activity", "activity-alias", "service", "receiver"]
    xml = a.get_AndroidManifest()
    for tag in find_tags:
        for item in xml.getElementsByTagName(tag):
            name = item.getAttribute("android:name")
            exported = item.getAttribute("android:exported")
            permission = item.getAttribute("android:permission")
            has_any_actions_in_intent_filter = False
            if (not isNullOrEmptyString(name)) and (exported.lower() !=
                                                    "false"):

                is_ready_to_check = False
                is_launcher = False
                has_any_non_google_actions = False
                isSyncAdapterService = False
                for sitem in item.getElementsByTagName("intent-filter"):
                    for ssitem in sitem.getElementsByTagName("action"):
                        has_any_actions_in_intent_filter = True

                        action_name = ssitem.getAttribute("android:name")
                        if (not action_name.startswith("android.")) and (
                                not action_name.startswith("com.android.")):
                            has_any_non_google_actions = True

                        if (action_name == "android.content.SyncAdapter"):
                            isSyncAdapterService = True

                    for ssitem in sitem.getElementsByTagName("category"):
                        category_name = ssitem.getAttribute("android:name")
                        if category_name == "android.intent.category.LAUNCHER":
                            is_launcher = True

                # exported="true" or exported not set
                if exported == "":
                    if has_any_actions_in_intent_filter:
                        # CHECK
                        is_ready_to_check = True

                elif exported.lower() == "true":  # exported = "true"
                    # CHECK
                    is_ready_to_check = True

                if (is_ready_to_check) and (not is_launcher):
                    list_ready_to_check.append(
                        (tag, a.format_value(name), exported, permission,
                         has_any_non_google_actions,
                         has_any_actions_in_intent_filter,
                         isSyncAdapterService))

    list_implicit_service_components = []
    list_alerting_exposing_components_NonGoogle = []
    list_alerting_exposing_components_Google = []
    for i in list_ready_to_check:
        component = i[0]
        permission = i[3]
        hasAnyNonGoogleActions = i[4]
        has_any_actions_in_intent_filter = i[5]
        isSyncAdapterService = i[6]
        is_dangerous = False
        if permission == "":  # permission is not set
            is_dangerous = True
        else:  # permission is set
            if permission in PermissionName_to_ProtectionLevel:
                protectionLevel = PermissionName_to_ProtectionLevel[permission]
                if (protectionLevel == PROTECTION_NORMAL) or (
                        protectionLevel == PROTECTION_DANGEROUS):
                    is_dangerous = True
            # else: #cannot find the mapping permission
            # 	is_dangerous = True

        if is_dangerous:
            if (component == "service") and (has_any_actions_in_intent_filter
                                             ) and (not isSyncAdapterService):
                list_implicit_service_components.append(i[1])

            if hasAnyNonGoogleActions:
                if i not in list_alerting_exposing_components_NonGoogle:
                    list_alerting_exposing_components_NonGoogle.append(i)
            else:
                if i not in list_alerting_exposing_components_Google:
                    list_alerting_exposing_components_Google.append(i)

    if list_alerting_exposing_components_NonGoogle or list_alerting_exposing_components_Google:
        if list_alerting_exposing_components_NonGoogle:
            writer.startWriter(
                "PERMISSION_EXPORTED", LEVEL_WARNING,
                u"[AS-lab048][OWASP-V2.3,V4.9,V6.4][MAST-4.2.2][工-4.1.2.5.3][M4] AndroidManifest Exported Components 檢查",
                u"""找到"exported"的組件(components)(除了 Launcher之外)用來接收外面應用程式的action(AndroidManifest.xml). 
這些組件可以被其他app使用，你應該增加[exported="false"]的屬性以防被其他人使用. 
你也可以在 "android:permission" 這個屬性之中使用 "signature" 或者 更高的保護權限去保護他.""" + "||" + \
u"""Find "exported" components (except Launcher) to receive actions from outside applications (AndroidManifest.xml). 
These components can be used by other apps and you should add the attribute [exported="false"] to prevent them from being used by others. 
You can also protect it with "signature" or higher protection privilege in the "android:permission" attribute.
""")

            for i in list_alerting_exposing_components_NonGoogle:
                writer.write(("%10s => %s") % (i[0], i[1]))

        # if list_alerting_exposing_components_Google:
        #     writer.startWriter(
        #         "PERMISSION_EXPORTED_GOOGLE", LEVEL_NOTICE,
        #         u"[AS-lab048][OWASP-V2.3,V4.9,V6.4][MAST-4.2.2][工-4.1.2.5.3][M4] AndroidManifest Exported Components 檢查 2",
        #         u"找到\"exported\"的組件(components)(除了 Launcher之外)用來接收外面應用程式的action(AndroidManifest.xml):"
        #     )

        #     for i in list_alerting_exposing_components_Google:
        #         writer.write(("%10s => %s") % (i[0], i[1]))
    # else:
    #     writer.startWriter(
    #         "PERMISSION_EXPORTED", LEVEL_INFO,
    #         u"[AS-lab048][OWASP-V2.3,V4.9,V6.4][MAST-4.2.2][工-4.1.2.5.3][M4]AndroidManifest Exported Components 檢查",
    #         u"沒有找到\"exported\"的組件(components)(除了 Launcher之外)用來接收外面應用程式的action(AndroidManifest.xml)."
    #     )

    # ------------------------------------------------------------------------
    # [lab_049] - AndroidManifest ContentProvider Exported 檢查
    # "exported" checking (provider):
    # android:readPermission, android:writePermission, android:permission
    list_ready_to_check = []

    xml = a.get_AndroidManifest()
    for item in xml.getElementsByTagName("provider"):
        name = item.getAttribute("android:name")
        exported = item.getAttribute("android:exported")

        if (not isNullOrEmptyString(name)) and (exported.lower() != "false"):
            # exported is only "true" or non-set
            permission = item.getAttribute("android:permission")
            readPermission = item.getAttribute("android:readPermission")
            writePermission = item.getAttribute("android:writePermission")
            has_exported = True if (exported != "") else False

            list_ready_to_check.append(
                (a.format_value(name), exported, permission, readPermission,
                 writePermission, has_exported))

    # providers that Did not set exported
    list_alerting_exposing_providers_no_exported_setting = []
    list_alerting_exposing_providers = []  # provider with "true" exported
    for i in list_ready_to_check:  # only exist "exported" provider or not set
        exported = i[1]
        permission = i[2]
        readPermission = i[3]
        writePermission = i[4]
        has_exported = i[5]

        is_dangerous = False
        list_perm = []
        if permission != "":
            list_perm.append(permission)
        if readPermission != "":
            list_perm.append(readPermission)
        if writePermission != "":
            list_perm.append(writePermission)

        if list_perm:  # among "permission" or "readPermission" or "writePermission", any of the permission is set
            # (1)match any (2)ignore permission that is not found
            for self_defined_permission in list_perm:
                if self_defined_permission in PermissionName_to_ProtectionLevel:
                    protectionLevel = PermissionName_to_ProtectionLevel[
                        self_defined_permission]
                    if (protectionLevel == PROTECTION_NORMAL) or (
                            protectionLevel == PROTECTION_DANGEROUS):
                        is_dangerous = True
                        break
            # permission is not set, it will depend on the Android system
            if (exported == "") and (int_target_sdk >= 17) and (is_dangerous):
                list_alerting_exposing_providers_no_exported_setting.append(i)

        else:  # none of any permission
            if exported.lower() == "true":
                is_dangerous = True
            # permission is not set, it will depend on the Android system
            elif (exported == "") and (int_target_sdk >= 17):
                list_alerting_exposing_providers_no_exported_setting.append(i)

        if is_dangerous:
            # exported="true" and none of the permission are set => of course dangerous
            list_alerting_exposing_providers.append(i)

    if list_alerting_exposing_providers or list_alerting_exposing_providers_no_exported_setting:
        if list_alerting_exposing_providers_no_exported_setting:  # providers that Did not set exported

            writer.startWriter(
                "PERMISSION_PROVIDER_IMPLICIT_EXPORTED", LEVEL_CRITICAL,
                u"[AS-lab049][OWASP-V4.9,V6.4][MAST-4.2.1][工-4.1.2.5.3][M4] AndroidManifest ContentProvider Exported 檢查",
                u"""我們強烈建議你詳細指明"exported"這個屬性(AndroidManifest.xml).
  對 Android"android:targetSdkVersion" < 17,exported的值對於ContentProvider來說預設是"true".
  對 Android"android:targetSdkVersion" >= 17,exported的值對於ContentProvider來說預設是"false".
代表說如果你沒有詳細的設定"android:exported",對於Android<4.2的手機你將會暴露出你的ContentProvider.
即使你將provider的permission設為[protectionalLevel="normal"]，在Android>=4.2的情況下，其他app仍然不能存取因為預設值為true
請仍然將'exported'設為'true'如果你要讓其他app存取他的話(使用保護權限為 "signature"的方法保護)，或者設為false如果你不想的話
請仍然將'exported'設為'true'如果你已經設定好"permission", "writePermission" or "readPermission" 為"signature"或更高的保護權限
因為其他Android>=4.2的手機即使是同個簽名的情況下是無法存取的
相關文獻http://developer.android.com/guide/topics/manifest/provider-element.html#exported
有漏洞的 ContentProvider範例:
  (1)https://www.nowsecure.com/mobile-security/ebay-android-content-provider-injection-vulnerability.html
  (2)http://blog.trustlook.com/2013/10/23/ebay-android-content-provider-information-disclosure-vulnerability/
  """ + "||" + u"""We strongly recommend you to specify the attribute "exported" in detail (AndroidManifest.xml).
  For Android "android:targetSdkVersion" < 17, the value of exported is "true" by default for ContentProvider.
  For Android "android:targetSdkVersion" >= 17, the value of exported is "false" by default for ContentProvider.
It means that if you don't set "android:exported" in detail, you will expose your ContentProvider for Android <4.2 phones.
Even if you set the provider's permission to [protectionLevel="normal"], in case of Android>=4.2, other apps still can't access it because the default value is true.
Please still set 'exported' to 'true' if you want to allow other apps to access it (using the protection method with "signature" protection), or set it to false if you don't want to.
Please still set 'exported' to 'true' if you have set "permission", "writePermission" or "readPermission" to "signature" or higher.
Because other phones with Android>=4.2 can't access it even if it's the same signature.
Related documentation http://developer.android.com/guide/topics/manifest/provider-element.html#exported
Example of a vulnerable ContentProvider:
  (1)https://www.nowsecure.com/mobile-security/ebay-android-content-provider-injection-vulnerability.html
  (2)http://blog.trustlook.com/2013/10/23/ebay-android-content-provider-information-disclosure-vulnerability/
  """)

            for i in list_alerting_exposing_providers_no_exported_setting:
                writer.write(("%10s => %s") % ("provider", i[0]))

        if list_alerting_exposing_providers:  # provider with "true" exported and not enough permission protected on it

            writer.startWriter(
                "PERMISSION_PROVIDER_EXPLICIT_EXPORTED", LEVEL_CRITICAL,
                u"[AS-lab049][OWASP-V4.9,V6.4][工-4.1.2.5.3][M4] AndroidManifest ContentProvider Exported 檢查",
                u"""找到"exported"的Content provider讓其他app可以存取他(AndroidManifest.xml). 你應該修改屬性到[exported="false"] 或者將保護權限設為 "signature" .
有漏洞的 ContentProvider範例: 
  (1)https://www.nowsecure.com/mobile-security/ebay-android-content-provider-injection-vulnerability.html
  (2)http://blog.trustlook.com/2013/10/23/ebay-android-content-provider-information-disclosure-vulnerability/
  """ + "||" + """Find the "exported" content provider for other apps to access it (AndroidManifest.xml). You should change the attribute to [exported="false"] or set the protection permission to "signature".
Example of a vulnerable ContentProvider: 
  (1)https://www.nowsecure.com/mobile-security/ebay-android-content-provider-injection-vulnerability.html
  (2)http://blog.trustlook.com/2013/10/23/ebay-android-content-provider-information-disclosure-vulnerability/
  """)
            for i in list_alerting_exposing_providers:
                writer.write(("%10s => %s") % ("provider", i[0]))

    # ------------------------------------------------------------------------
    # [lab_050] - AndroidManifest intent-filter checking:
    """
		Example misconfiguration:
			<receiver android:name=".service.push.SystemBroadcastReceiver">
	            <intent-filter android:enabled="true" android:exported="false">
	                <action android:name="android.intent.action.BOOT_COMPLETED" />
	                <action android:name="android.intent.action.USER_PRESENT" />
	            </intent-filter>
	            <intent-filter android:enabled="true" android:exported="false">
	            </intent-filter>
	        </receiver>

	    Detected1: <intent-filter android:enabled="true" android:exported="false">
	    Detected2: No actions in "intent-filter"
	"""

    find_tags = ["activity", "activity-alias", "service", "receiver"]
    xml = a.get_AndroidManifest()
    list_wrong_intent_filter_settings = []
    list_no_actions_in_intent_filter = []
    for tag in find_tags:
        for sitem in xml.getElementsByTagName(tag):
            isDetected1 = False
            isDetected2 = False
            for ssitem in sitem.getElementsByTagName("intent-filter"):
                if (ssitem.getAttribute("android:enabled") !=
                        "") or (ssitem.getAttribute("android:exported") != ""):
                    isDetected1 = True
                if len(sitem.getElementsByTagName("action")) == 0:
                    isDetected2 = True
            if isDetected1:
                list_wrong_intent_filter_settings.append(
                    (tag, sitem.getAttribute("android:name")))
            if isDetected2:
                list_no_actions_in_intent_filter.append(
                    (tag, sitem.getAttribute("android:name")))

    if list_wrong_intent_filter_settings or list_no_actions_in_intent_filter:
        if list_wrong_intent_filter_settings:
            writer.startWriter(
                "PERMISSION_INTENT_FILTER_MISCONFIG", LEVEL_WARNING,
                u"[AS-lab050][OWASP-V6.2][MAST-4.2.2] AndroidManifest \"intent-filter\" 設定檢查",
                u"""在"intent-filter" 裡的這些components配置錯誤 (AndroidManifest.xml). 
 配置 "intent-filter" 不應該有 "android:exported" 或 "android:enabled" 屬性. 
 參考: http://developer.android.com/guide/topics/manifest/intent-filter-element.html
 """+ "||" + u"""These components in "intent-filter" are configured incorrectly (AndroidManifest.xml). 
 The configuration "intent-filter" should not have "android:exported" or "android:enabled" attributes. 
 Reference: http://developer.android.com/guide/topics/manifest/intent-filter-element.html""")
            for tag, name in list_wrong_intent_filter_settings:
                writer.write(("%10s => %s") % (tag, a.format_value(name)))

        if list_no_actions_in_intent_filter:
            writer.startWriter(
                "PERMISSION_INTENT_FILTER_MISCONFIG", LEVEL_CRITICAL,
                u"[AS-lab050][OWASP-V6.2][MAST-4.2.2] AndroidManifest \"intent-filter\" 設定檢查",
                u"""在"intent-filter" 裡的這些components配置錯誤 (AndroidManifest.xml).
 配置 "intent-filter" 應該至少要有一個 "action".
 參考: http://developer.android.com/guide/topics/manifest/intent-filter-element.html
 """+ "||" + u"""These components in "intent-filter" are configured incorrectly (AndroidManifest.xml).
 There should be at least one "action" in the "intent-filter" configuration.
 Reference: http://developer.android.com/guide/topics/manifest/intent-filter-element.html""")
            for tag, name in list_no_actions_in_intent_filter:
                writer.write(("%10s => %s") % (tag, a.format_value(name)))

    # ------------------------------------------------------------------------
    # [lab_051] - Implicit Service (** Depend on: "exported" checking (activity, activity-alias, service, receiver) **)

    if list_implicit_service_components:
        writer.startWriter(
            "PERMISSION_IMPLICIT_SERVICE", LEVEL_CRITICAL,
            u"[AS-lab051][OWASP-V2.1][MAST-4.2.7] Implicit Service Checking",
            u"""為了保護app的安全， 在開始啟動service時總是使用explicit intent 而且不要對你的service使用 intent filters . 使用 implicit intent去啟動service 是一個安全的保障因為你不能確切的知道service會對intent回應什麼,而且使用者不能在service開啟時看見.
相關文獻:http://developer.android.com/guide/components/intents-filters.html#Types""" + "||" +  u"""To protect the security of the app, always use explicit intent when starting the service and don't use intent filters on your service. Using implicit intent to start the service is a security measure because you don't know exactly what the service will respond to the intent and the user can't see it when the service is opened.
Related documents:http://developer.android.com/guide/components/intents-filters.html#Types""" ,
            ["Implicit_Intent"])

        for name in list_implicit_service_components:
            writer.write(("=> %s") % (a.format_value(name)))

    # else:
    #     writer.startWriter(
    #         "PERMISSION_IMPLICIT_SERVICE", LEVEL_INFO,
    #         u"[AS-lab051][OWASP-V2.1][MAST-4.2.7] Implicit Service Checking",
    #         "No dangerous implicit service.", ["Implicit_Intent"])

    # ------------------------------------------------------------------------
    # [lab_052] - SQLite databases

    is_using_android_dbs = vmx.get_tainted_packages().has_android_databases(
        filteringEngine.get_filtering_regexp())

    if is_using_android_dbs:
        if int_min_sdk < 15:
            writer.startWriter(
                "DB_SQLITE_JOURNAL", LEVEL_NOTICE,
                u"[AS-lab052][OWASP-V2.1][MAST-4.2.7][工-4.1.5.1.1][CVE-2011-3901]Android SQLite 資料庫漏洞檢查",
                u"""這個app在使用 Android SQLite databases.
在 Android 4.0 版本前, Android 有 SQLite Journal Information Disclosure 的危險.
這唯一的解決方法就是使用者要升級到 Android > 4.0 無法自行解決(但是你可以使用"SQLCipher"或其他涵式庫加密你的資料庫和日誌).
Proof-Of-Concept 參考:
(1) http://blog.watchfire.com/files/androidsqlitejournal.pdf
 """+ "||" + """This app is using Android SQLite databases.
Prior to Android 4.0, Android had the risk of SQLite Journal Information Disclosure.
The only solution to this is for users to upgrade to Android > 4.0. There is no way to fix this on your own (but you can encrypt your databases and journals using "SQLCipher" or other implicit libraries).
Proof-Of-Concept reference:
(1) http://blog.watchfire.com/files/androidsqlitejournal.pdf""", ["Database"], "CVE-2011-3901")
        else:
            writer.startWriter(
                "DB_SQLITE_JOURNAL", LEVEL_NOTICE,
                u"[AS-lab052][OWASP-V2.1][MAST-4.2.7][工-4.1.5.1.1][CVE-2011-3901]Android SQLite 資料庫漏洞檢查",
                u"這個app在使用Android SQLite databases 但是他沒有遭受 SQLite Journal Information Disclosure 的危險." + "||" +
                u"This app is using Android SQLite databases but he is not at risk of SQLite Journal Information Disclosure.",
                ["Database"], "CVE-2011-3901")

    # ------------------------------------------------------------------------
    # [lab_053](*) - hecking whether the app is using SQLCipher: Reference to <<Essential_Block_1>>

    if isUsingSQLCipher:
        writer.startWriter(
            "DB_SQLCIPHER", LEVEL_NOTICE,
            u"[AS-lab053][OWASP-V2.1][MAST-4.2.7][工-4.1.2.3.6][M2] Android SQLite 資料庫加密 (SQLCipher)",
            u"這個app在使用SQLCipher(http://sqlcipher.net/) 來加密或解密資料庫." + "||" + u"This app is using SQLCipher(http://sqlcipher.net/) to encrypt or decrypt the database.",
            ["Database"])

        # Don't do the exclusion checking on this one because it's not needed
        path_sqlcipher_dbs = vmx.get_tainted_packages(
        ).search_sqlcipher_databases()

        if path_sqlcipher_dbs:
            # Get versions:
            has_version1or0 = False
            has_version2 = False
            for _, version in path_sqlcipher_dbs:
                if version == 1:
                    has_version1or0 = True
                if version == 2:
                    has_version2 = True

            if has_version1or0:
                writer.write(
                    "使用 \"SQLCipher for Android\" (Library version: 1.X or 0.X), package name: \"info.guardianproject.database\""
                )
            if has_version2:
                writer.write(
                    "使用 \"SQLCipher for Android\" (Library version: 2.X or higher), package name: \"net.sqlcipher.database\""
                )

            # Dumping:
            for db_path, version in path_sqlcipher_dbs:
                writer.show_Path(d, db_path)

    # ------------------------------------------------------------------------
    # [lab_054] - Find "SQLite Encryption Extension (SEE) on Android"

    has_SSE_databases = False
    result = get_androguard('/lab_054')
    if result and 'results' in result:
        for item in result['results']:
            if item.get('class_found', False):  
                has_SSE_databases = True
                break

    if has_SSE_databases:
         writer.startWriter(
            "DB_SEE", LEVEL_NOTICE,
            u"[AS-lab054][OWASP-V2.1][MAST-4.2.7][工-4.1.2.3.6][M2] Android SQLite 資料庫加密 (SQLite Encryption Extension (SEE))",
            u"這個app在使用SQLite Encryption Extension (SEE) on Android (http://www.sqlite.org/android) 來加密或解密資料庫." + "||" + u"This app is using SQLite Encryption Extension (SEE) on Android (http://www.sqlite.org/android) to encrypt or decrypt the database.",
            ["Database"])

    # ------------------------------------------------------------------------
    # [lab_055] - Searching SQLite "PRAGMA key" encryption

    result_sqlite_encryption_androguard = get_androguard('/lab_055')
    
    if result_sqlite_encryption_androguard and isinstance(result_sqlite_encryption_androguard, dict):
        pragma_key_strings = result_sqlite_encryption_androguard.get('pragma_key_strings', [])
        pragma_key_methods = result_sqlite_encryption_androguard.get('pragma_key_methods', [])
        total_findings = result_sqlite_encryption_androguard.get('count', 0)
        
        if total_findings > 0:
            writer.startWriter("HACKER_DB_KEY", LEVEL_NOTICE,
                               u"[AS-lab055][MAST-4.2.7] 金鑰用來加密 Android SQLite 資料庫",
                               u"發現在使用對稱金鑰(PRAGMA key) 來加密 SQLite 資料庫. \n相關的程式碼:" + "||" + u"Found using PRAGMA key to encrypt SQLite database. \n related code:",
                               ["Database", "Hacker"])
            
            # output PRAGMA key string result
            for item in pragma_key_strings:
                writer.write(item['class'] + "->" + item['method'] + "(): " + item['string'])
            
            # output PRAGMA key method result
            for item in pragma_key_methods:
                writer.write(item['class'] + "->" + item['method'] + "(): " + item['instruction'])
 



    # ------------------------------------------------------------------------
    # [lab_056] - Searching checking root or not:
    result_possibly_check_root = efficientStringSearchEngine.get_search_result_by_match_id(
        "$__possibly_check_root__")
    result_possibly_check_su = efficientStringSearchEngine.get_search_result_by_match_id(
        "$__possibly_check_su__")
    result_possibly_root_total = []

    if result_possibly_check_root:
        result_possibly_root_total.extend(result_possibly_check_root)

    if result_possibly_check_su:
        result_possibly_root_total.extend(result_possibly_check_su)

    result_possibly_root_total = filteringEngine.filter_efficient_search_result_value(
        result_possibly_root_total)

    if result_possibly_root_total:
        writer.startWriter(
            "COMMAND_MAYBE_SYSTEM", LEVEL_NOTICE,
            "[AS-lab056][OWASP-V6.10] Executing \"root\" or System Privilege Checking",
            u"這個app可能在檢查管理者權限、掛載filesystem的指令或是監看系統:" + "||" + u"The app may be checking administrator privileges, mounting filesystem commands or monitoring the system:", 
            ["Command"])

        list_possible_root = []
        list_possible_remount_fs = []
        list_possible_normal = []

        # strip the duplicated items
        for found_string, method in set(result_possibly_root_total):
            if ("'su'" == found_string) or ("/su" in found_string):
                # 3rd parameter: show string or not
                list_possible_root.append((found_string, method, True))
            elif "mount" in found_string:  # mount, remount
                list_possible_remount_fs.append((found_string, method, True))
            else:
                list_possible_normal.append((found_string, method, True))

        lst_ordered_finding = []
        lst_ordered_finding.extend(list_possible_root)
        lst_ordered_finding.extend(list_possible_remount_fs)
        lst_ordered_finding.extend(list_possible_normal)

        for found_string, method, show_string in lst_ordered_finding:
            if show_string:
                writer.write(method.get_class_name() + "->" + method.get_name(
                ) + method.get_descriptor() + "  => " + found_string)
            else:
                writer.write(method.get_class_name() + "->" +
                             method.get_name() + method.get_descriptor())

    # ------------------------------------------------------------------------
    # [lab_057] - Sensitive device / subscriber identifier reads (migrated to androguard_server)
    # 擴充: 不只 getDeviceId，補 getImei / getMeid / getSubscriberId(IMSI) /
    # getLine1Number(門號) / getSimSerialNumber(SIM 序號)
    result_lab057 = get_androguard('/lab_057')

    if result_lab057 and isinstance(result_lab057, dict) and result_lab057.get('has_finding'):
        warning_057 = result_lab057.get('warning', [])

        writer.startWriter(
            "SENSITIVE_DEVICE_ID", LEVEL_WARNING,
            u"[AS-lab057][MAST-4.2.2] 獲取裝置/用戶識別碼 (IMEI/IMSI/門號)",
            u"此 app 透過 TelephonyManager 讀取硬體/用戶識別碼: "
            u"getDeviceId()/getImei() -> IMEI、getMeid() -> MEID、"
            u"getSubscriberId() -> IMSI (SIM 用戶身分,裝置重置後仍可追蹤同一用戶)、"
            u"getLine1Number() -> 手機門號、getSimSerialNumber() -> SIM 序號。"
            u"這些都是不可重置或高度敏感的識別碼,Android 10+ 已限制需特權權限才能讀取,"
            u"常被間諜軟體用於裝置指紋與用戶追蹤。建議改用可重置的 "
            u"Firebase Installation ID / App Set ID / UUID。"
            u" Ref: https://developer.android.com/identity/user-data-ids"
            + "||" +
            u"This app reads hardware / subscriber identifiers via TelephonyManager: "
            u"getDeviceId()/getImei() -> IMEI, getMeid() -> MEID, "
            u"getSubscriberId() -> IMSI (SIM subscriber id; tracks the same user even after device reset), "
            u"getLine1Number() -> phone number, getSimSerialNumber() -> SIM serial. "
            u"These are non-resettable / highly sensitive identifiers; Android 10+ restricts them to "
            u"privileged apps and they are commonly abused by spyware for device fingerprinting. "
            u"Prefer resettable IDs such as Firebase Installation ID / App Set ID / UUID."
            u" Ref: https://developer.android.com/identity/user-data-ids",
            ["Sensitive_Information"])

        if warning_057:
            writer.write(u"[WARNING: %d]" % len(warning_057))
            for f in warning_057:
                cls = f.get('class', '')
                if cls.startswith('L') and cls.endswith(';'):
                    cls = cls[1:-1].replace('/', '.')
                writer.write(u"  %s.%s()  api=%s  reason=%s" % (
                    cls, f.get('method', ''), f.get('api', ''), f.get('reason', '')))

    # ------------------------------------------------------------------------
    # [lab_058] - Settings.Secure.ANDROID_ID read (migrated to androguard_server)
    # const-string lookback 確認參數為 "android_id"，與 lab_057 同模式統一裝置指紋類
    result_lab058 = get_androguard('/lab_058')

    if result_lab058 and isinstance(result_lab058, dict) and result_lab058.get('has_finding'):
        warning_058 = result_lab058.get('warning', [])

        writer.startWriter(
            "SENSITIVE_SECURE_ANDROID_ID", LEVEL_WARNING,
            u"[AS-lab058][MAST-4.2.2] 讀取 Settings.Secure.ANDROID_ID",
            u"此 app 讀取 Settings.Secure.ANDROID_ID。"
            u"ANDROID_ID 是一組裝置層級的識別碼,常被用於裝置指紋與用戶追蹤。"
            u"它在「恢復原廠設定」後才會改變,且早期不同廠牌裝置可能回傳相同值,"
            u"不適合當作可靠或可重置的識別碼。建議改用可重置的 "
            u"Firebase Installation ID / App Set ID / UUID。"
            u" Ref: https://developer.android.com/identity/user-data-ids"
            + "||" +
            u"This app reads Settings.Secure.ANDROID_ID. ANDROID_ID is a "
            u"device-scoped identifier commonly used for device fingerprinting "
            u"and user tracking. It only changes on a factory reset and some "
            u"older devices return the same value across handsets, so it is not "
            u"a reliable or resettable identifier. Prefer a resettable id such "
            u"as the Firebase Installation ID / App Set ID / UUID."
            u" Ref: https://developer.android.com/identity/user-data-ids",
            ["Sensitive_Information"])

        if warning_058:
            writer.write(u"[WARNING: %d]" % len(warning_058))
            for f in warning_058:
                cls = f.get('class', '')
                if cls.startswith('L') and cls.endswith(';'):
                    cls = cls[1:-1].replace('/', '.')
                writer.write(u"  %s.%s()  api=%s  reason=%s" % (
                    cls, f.get('method', ''), f.get('api', ''), f.get('reason', '')))

    # ------------------------------------------------------------------------
    # [lab_059] - Checking sending SMS code
    """
	  Example:
		Landroid/telephony/SmsManager;->sendDataMessage(Ljava/lang/String; Ljava/lang/String; S [B Landroid/app/PendingIntent; Landroid/app/PendingIntent;)V
		Landroid/telephony/SmsManager;->sendMultipartTextMessage(Ljava/lang/String; Ljava/lang/String; Ljava/util/ArrayList; Ljava/util/ArrayList; Ljava/util/ArrayList;)V
		Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String; Ljava/lang/String; Ljava/lang/String; Landroid/app/PendingIntent; Landroid/app/PendingIntent;)V
	"""

    list_sms_signatures = [(
        "sendDataMessage",
        "(Ljava/lang/String; Ljava/lang/String; S [B Landroid/app/PendingIntent; Landroid/app/PendingIntent;)V"
    ), (
        "sendMultipartTextMessage",
        "(Ljava/lang/String; Ljava/lang/String; Ljava/util/ArrayList; Ljava/util/ArrayList; Ljava/util/ArrayList;)V"
    ), ("sendTextMessage",
        "(Ljava/lang/String; Ljava/lang/String; Ljava/lang/String; Landroid/app/PendingIntent; Landroid/app/PendingIntent;)V"
        )]

    path_sms_sending = vmx.get_tainted_packages(
    ).search_class_methodlist_exact_match("Landroid/telephony/SmsManager;",
                                          list_sms_signatures)
    path_sms_sending = filteringEngine.filter_list_of_paths(
        d, path_sms_sending)

    if path_sms_sending:
        writer.startWriter(
            "SENSITIVE_SMS", LEVEL_WARNING,
            u"[AS-lab059][OWASP-V5.5] 傳送SMS訊息的code",
            u"這app有傳送SMS訊息的code (sendDataMessage, sendMultipartTextMessage or sendTextMessage):" + "||" + u"This app has the code to send SMS messages (sendDataMessage, sendMultipartTextMessage or sendTextMessage):"
        )
        writer.show_Paths(d, path_sms_sending)
    
    # ------------------------------------------------------------------------
    # [lab_060] - Weak Cipher detection (Cipher only, hash moved to lab_079)
    # 解析 transformation 字串 (alg/mode/padding), 按真實風險分級
    def _fmt_cls(c):
        if c.startswith('L') and c.endswith(';'):
            return c[1:-1].replace('/', '.')
        return c

    result_lab060 = get_androguard('/lab_060')

    if result_lab060 and isinstance(result_lab060, dict) and result_lab060.get('has_finding'):
        verdict_060  = result_lab060.get('verdict', 'WARNING')
        critical_060 = result_lab060.get('critical', [])
        warning_060  = result_lab060.get('warning', [])
        info_060     = result_lab060.get('info', [])
        unknown_060  = result_lab060.get('unknown', [])

        if verdict_060 == 'CRITICAL':
            level_060 = LEVEL_CRITICAL
        elif verdict_060 == 'WARNING':
            level_060 = LEVEL_WARNING
        else:
            level_060 = LEVEL_INFO

        writer.startWriter(
            "LAB_060_WEAK_CIPHER", level_060,
            u"[AS-lab060][MAS-4.1.2.3.6][MASVS-CRYPTO-1][CWE-327] 弱對稱/非對稱加密演算法檢查",
            u"解析 Cipher.getInstance(transformation) 的字串參數 (algorithm/mode/padding),"
            u"依加密強度分級。"
            u"CRITICAL: ECB mode (任何演算法都受影響) / DES / RC4 / RC2 / Blowfish; "
            u"WARNING: CBC mode (未驗證 IV 來源) / 3DES (DESede); "
            u"INFO: GCM / CCM / ChaCha20-Poly1305 等 authenticated encryption。"
            u"注意: 雜湊函式 (MessageDigest) 不是加密,已獨立為 lab_079 處理。"
            u"本次未涵蓋 (留待後續): hardcoded IV 偵測 / key size 強度檢查 / "
            u"PBKDF2 iteration count / KeyGenParameterSpec 配置稽核。"
            u" Ref: https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-1/"
            + "||" +
            u"Parses Cipher.getInstance(transformation) string arguments "
            u"(algorithm/mode/padding) and classifies by cryptographic strength. "
            u"CRITICAL: ECB mode (any algorithm) / DES / RC4 / RC2 / Blowfish; "
            u"WARNING: CBC mode (no IV verification) / 3DES (DESede); "
            u"INFO: GCM / CCM / ChaCha20-Poly1305 authenticated encryption. "
            u"Note: hash functions (MessageDigest) are NOT encryption and are covered in lab_079. "
            u"Not yet covered (future work): hardcoded IV detection / key size enforcement / "
            u"PBKDF2 iteration count / KeyGenParameterSpec audit."
            u" Ref: https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-1/",
            ["Crypto", "Cipher"])

        def _fmt_cipher(f):
            return u"  %s.%s()  transformation=%s  reason=%s" % (
                _fmt_cls(f.get('class', '')), f.get('method', ''),
                f.get('transformation', ''), f.get('reason', ''))

        def _fmt_key(f):
            return u"  %s.%s()  key_source=%s  iv_source=%s  reason=%s" % (
                _fmt_cls(f.get('class', '')), f.get('method', ''),
                f.get('key_source', ''), f.get('iv_source', ''),
                f.get('reason', ''))

        # Only output CRITICAL findings — keep report compact for table display
        if critical_060:
            cipher_c = [f for f in critical_060 if 'transformation' in f]
            key_c    = [f for f in critical_060 if 'key_source'     in f]
            writer.write(u"[CRITICAL: %d]" % len(critical_060))
            if cipher_c:
                writer.write(u"  -- Cipher transformation --")
                for f in cipher_c:
                    writer.write(_fmt_cipher(f))
            if key_c:
                writer.write(u"  -- Key material --")
                for f in key_c:
                    writer.write(_fmt_key(f))

    # ------------------------------------------------------------------------
    # [lab_079] - Weak Hash function detection (split from lab_060)
    # 雜湊不是加密 — 沒有 key, 不可逆。獨立為一個 lab 以符合正確密碼學分類
    result_lab079 = get_androguard('/lab_079')

    if result_lab079 and isinstance(result_lab079, dict) and result_lab079.get('has_finding'):
        verdict_079  = result_lab079.get('verdict', 'WARNING')
        critical_079 = result_lab079.get('critical', [])
        info_079     = result_lab079.get('info', [])
        unknown_079  = result_lab079.get('unknown', [])

        if verdict_079 == 'CRITICAL':
            level_079 = LEVEL_CRITICAL
        elif verdict_079 == 'WARNING':
            level_079 = LEVEL_WARNING
        else:
            level_079 = LEVEL_INFO

        writer.startWriter(
            "LAB_079_WEAK_HASH", level_079,
            u"[AS-lab079][MAS-4.1.2.3.6][MASVS-CRYPTO-1][CWE-327][CWE-328] 弱雜湊函式檢查",
            u"解析 MessageDigest.getInstance(algorithm) 的字串參數,辨識已破解或 collision-prone 的雜湊。"
            u"雜湊函式不是加密 — 沒有 key, 不可逆,單純把任意 input 轉成固定長度指紋。"
            u"CRITICAL: MD5 / MD2 / MD4 / SHA-1 (已被破解或 collision-prone); "
            u"INFO: SHA-256 / SHA-384 / SHA-512 / SHA-3 系列 (NIST 推薦)。"
            u"本次未涵蓋 (留待後續): 用途分類 (password hash vs file checksum vs cache key) / "
            u"HMAC 演算法強度 / 迭代雜湊偵測 (PBKDF2)。"
            u" Ref: https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-1/"
            + "||" +
            u"Parses MessageDigest.getInstance(algorithm) string arguments and identifies broken "
            u"or collision-prone hashes. Hashing is NOT encryption: no key, one-way, fixed-length output. "
            u"CRITICAL: MD5 / MD2 / MD4 / SHA-1 (broken or collision-prone); "
            u"INFO: SHA-256 / SHA-384 / SHA-512 / SHA-3 family (NIST recommended). "
            u"Not yet covered (future work): usage classification (password hash vs file checksum vs "
            u"cache key) / HMAC algorithm strength / iterated hashing detection (PBKDF2)."
            u" Ref: https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-1/",
            ["Crypto", "Hash"])

        # Only output CRITICAL findings — keep report compact for table display
        if critical_079:
            writer.write(u"[CRITICAL: %d]" % len(critical_079))
            for f in critical_079:
                writer.write(u"  %s.%s()  algorithm=%s  reason=%s" % (
                    _fmt_cls(f.get('class', '')), f.get('method', ''),
                    f.get('algorithm', ''), f.get('reason', '')))

    # ------------------------------------------------------------------------
    # [lab_080] - Sensitive data copied to system clipboard
    # same-method co-occurrence: clipboard write API + 敏感關鍵字 const-string 才標記
    result_lab080 = get_androguard('/lab_080')

    if result_lab080 and isinstance(result_lab080, dict) and result_lab080.get('has_finding'):
        verdict_080  = result_lab080.get('verdict', 'WARNING')
        critical_080 = result_lab080.get('critical', [])
        warning_080  = result_lab080.get('warning', [])

        if verdict_080 == 'CRITICAL':
            level_080 = LEVEL_CRITICAL
        elif verdict_080 == 'WARNING':
            level_080 = LEVEL_WARNING
        else:
            level_080 = LEVEL_INFO

        writer.startWriter(
            "LAB_080_CLIPBOARD_SENSITIVE", level_080,
            u"[AS-lab080][MAS-4.1.2.3.11][MASVS-STORAGE-1][CWE-200] 剪貼簿敏感資料外洩檢查",
            u"任何 App (以及部分輸入法) 都能讀取系統全域剪貼簿,將密碼、PIN、卡號、token 等"
            u"敏感資料複製到剪貼簿會曝露給其他 App。本檢查採 same-method co-occurrence 啟發式: "
            u"在同一 method 內偵測到剪貼簿寫入 API (ClipboardManager.setPrimaryClip / setText) "
            u"且該 method 含敏感關鍵字 const-string 才標記。"
            u"CRITICAL: 明確敏感關鍵字 (password / pin / cvv / ssn / card / secret key); "
            u"WARNING: 可能敏感關鍵字 (token / account / auth / credential / otp)。"
            u"單純剪貼簿寫入但無敏感關鍵字 (如複製訂單編號、分享連結) 不報以避免噪音。"
            u" Ref: https://developer.android.com/privacy-and-security/risks/secure-clipboard-handling"
            + "||" +
            u"Any app (and some IMEs) can read the global system clipboard, so copying secrets "
            u"(passwords, PINs, card numbers, tokens) into it exposes them to other apps. This check "
            u"uses a same-method co-occurrence heuristic: a clipboard write API "
            u"(ClipboardManager.setPrimaryClip / setText) together with a sensitive-keyword const-string "
            u"in the same method. CRITICAL: explicit secret keyword (password / pin / cvv / ssn / card / "
            u"secret key); WARNING: possibly-sensitive keyword (token / account / auth / credential / otp). "
            u"Clipboard writes without any sensitive keyword (e.g. copying an order id or share link) are "
            u"NOT reported to avoid noise."
            u" Ref: https://developer.android.com/privacy-and-security/risks/secure-clipboard-handling",
            ["Clipboard", "Privacy"])

        if critical_080:
            writer.write(u"[CRITICAL: %d]" % len(critical_080))
            for f in critical_080:
                cls = f.get('class', '')
                if cls.startswith('L') and cls.endswith(';'):
                    cls = cls[1:-1].replace('/', '.')
                writer.write(u"  %s.%s()  keyword=%s  reason=%s" % (
                    cls, f.get('method', ''), f.get('keyword', ''), f.get('reason', '')))

        if warning_080:
            writer.write(u"[WARNING: %d]" % len(warning_080))
            for f in warning_080:
                cls = f.get('class', '')
                if cls.startswith('L') and cls.endswith(';'):
                    cls = cls[1:-1].replace('/', '.')
                writer.write(u"  %s.%s()  keyword=%s  reason=%s" % (
                    cls, f.get('method', ''), f.get('keyword', ''), f.get('reason', '')))

    #-----------------------------------------------------------------------------------
    # [AS-lab081] - 4.1.5.4.1 — 使用者輸入驗證 (型別 / 長度)
    # 掃 res/layout* 的輸入欄位, 檢查有無宣告 android:inputType 與 android:maxLength
    result_lab081 = get_androguard('/lab_081')
    warning_081   = result_lab081.get('warning', []) if isinstance(result_lab081, dict) else []

    # 報告只列出 WARNING (敏感 / 密碼欄位)。NOTICE (一般欄位缺 inputType) 仍會偵測並保留在
    # 檢測結果中, 但不寫進報告 —— 搜尋欄、備註欄不限制字元屬正常用法, 列出會稀釋重點。
    # 入口條件用 warning_081 而非 has_finding, 避免寫出沒有明細的空區塊。
    if warning_081:
        writer.startWriter(
            "INPUT_VALIDATION", LEVEL_WARNING,
            u"[AS-lab081][MAS-4.1.5.4.1][MASVS-CODE-4][M4] 使用者輸入驗證檢查",
            u"未限制使用者輸入的型別與長度時，攻擊者可輸入預期外的字元或超長字串，觸發 SQL Injection、命令注入、路徑穿越等注入攻擊，或造成後端處理異常；密碼類欄位若無長度上限，超長輸入可能造成雜湊運算資源耗盡。" u"\n\n"
            u"本檢查解析 res/layout 及其限定詞目錄（layout-land、layout-v21 等）下的 layout XML，找出 EditText / AutoCompleteTextView 系列欄位，檢查 android:inputType（型別限制，所有欄位皆檢查）與 android:maxLength（長度限制，僅檢查敏感／密碼類欄位，因一般欄位如搜尋欄、備註欄不設長度上限屬正常用法）。" u"\n\n"
            u"報告僅列出 WARNING（敏感／密碼類欄位缺少型別或長度限制）；一般輸入欄位缺少型別限制屬低風險，仍會偵測並保留於檢測結果，但不列入報告。" u"\n\n"
            u"限制：僅檢查 layout XML 的宣告；以程式碼實作的驗證（InputFilter）與程式化建立的介面（Jetpack Compose、WebView 表單）皆掃不到，建議對命中項目人工複查。" u"\n\n"
            u"參考: https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/ | https://developer.android.com/reference/android/widget/TextView#attr_android:inputType"
            + "||" +
            u"When user input has no declared type or length constraint, an attacker can supply unexpected characters or an overly long string, enabling SQL injection, command injection, path traversal, or backend processing failures; a password field with no length cap allows input long enough to exhaust hashing resources." u"\n\n"
            u"This check parses the layout XML under res/layout and its qualifier directories (layout-land, layout-v21, etc.), locates EditText / AutoCompleteTextView family fields, and verifies android:inputType (type constraint, checked on every field) and android:maxLength (length constraint, checked on sensitive / password fields only, since ordinary fields such as search or comment boxes legitimately have no length cap)." u"\n\n"
            u"Only WARNING findings (sensitive / password field missing a type or length constraint) are listed; an ordinary input field missing a type constraint is low risk and is still detected and kept in the result data, but omitted from the report." u"\n\n"
            u"Limitation: only the layout XML declarations are inspected; validation implemented in code (InputFilter) and programmatically built UI (Jetpack Compose, WebView forms) are not covered, so manual review of flagged items is recommended." u"\n\n"
            u"Ref: https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/ | https://developer.android.com/reference/android/widget/TextView#attr_android:inputType",
            [u"InputValidation", u"Injection"])

        # Detail 一律用英文並先 encode 成 UTF-8: vector_details 為中英文版報告共用,
        # 且 Writer.write() 會把 unicode 逃逸成 \xNN 字面文字。
        def _w081(line):
            writer.write(line.encode('utf-8'))

        # 每行格式: [等級] 版面檔 <元件 欄位定位> missing=缺少的屬性
        # Writer 每個 lab 最多收 10 行, 超過時留一行標示尚有幾筆。
        shown_081 = warning_081 if len(warning_081) <= 10 else warning_081[:9]

        for f in shown_081:
            # server 端 missing 為 "inputType (type constraint)", 報告只留屬性名
            missing_attrs = u", ".join(m.split(' ')[0] for m in f.get('missing', []))
            # 缺 maxLength 時附上現有型別, 幫助判斷該設多長
            declared      = f.get('input_type_readable')
            _w081(u"[%s] %s <%s %s> missing=%s%s" % (
                f.get('severity', ''), f.get('file', ''),
                f.get('tag', 'EditText'), f.get('field_label', ''),
                missing_attrs,
                (u"  (inputType=%s)" % declared) if declared else u""))

        if len(warning_081) > 10:
            _w081(u"... and %d more" % (len(warning_081) - 9))

    #-----------------------------------------------------------------------------------
    # [lab_061] - Checking shared_user_id
    sharedUserId = a.get_shared_user_id()
    sharedUserId_in_system = False

    if (sharedUserId == "android.uid.system"):
        sharedUserId_in_system = True

    if sharedUserId_in_system:
        writer.startWriter(
            "SHARED_USER_ID", LEVEL_NOTICE,
            u"[AS-lab061][MAST-4.2.2] AndroidManifest sharedUserId 檢查",
            u"這app使用 \"android.uid.system\" sharedUserId, 他需要\"system(uid=1000)\" 這個權限. 他必須被製造者或google的keystore簽名才能成功安裝在使用者的手機." + "||" + u"This app uses \"android.uid.system\" sharedUserId, which requires the permission \"system(uid=1000)\". It must be signed by the manufacturer or google keystore to be successfully installed on the user's phone.",
            ["System"])

    #-----------------------------------------------------------------------------------
    # [lab_062] - System shared_user_id + Master Key Vulnerability checking: (Depends on "Master Key Vulnerability checking")
    if sharedUserId_in_system and isMasterKeyVulnerability:
        writer.startWriter(
            "MASTER_KEY_SYSTEM_APP", LEVEL_CRITICAL,
            u"[AS-lab062][OWASP-V7.1][MAST-4.2.6][工-4.1.5.1.2][CVE-2013-4787] 使用Master Key漏洞去取得管理者權限",
            u"這app是一個惡意軟體, 他需要透過Master Key漏洞得到\"system(uid=1000)\" , 導致手機被取得管理者權限." + "||" + u"This app is a malware, he needs to get \"system(uid=1000)\" through the Master Key vulnerability, resulting in the phone being granted administrator privileges."
        )

    # ------------------------------------------------------------------------
    # [lab_063] - Unsafe file deletion check (migrated to androguard_server)
    # 舊版只要呼叫過 file.delete() 就標記, 在現代 (R8/ProGuard 混淆) APK 上幾乎全是
    # 第三方函式庫自己的快取清理雜訊 (例如 AndroidX 字型快取), 誤報率高。
    # 新版只在「同一個 method 內, delete() 呼叫跟敏感關鍵字字串同時出現」時才標記。
    result_lab063 = get_androguard('/lab_063')

    if result_lab063 and isinstance(result_lab063, dict) and result_lab063.get('has_finding'):
        results_063 = result_lab063.get('results', [])

        writer.startWriter(
            "FILE_DELETE", LEVEL_NOTICE,
            u"[AS-lab063][MAS-4.1.2.3.5][MASVS-STORAGE-2][M9]不安全的檔案刪除檢查",
            u"""偵測到 File.delete() 與敏感關鍵字 (password/token/secret 等) 出現在同一個 method 內。
任何你所刪除的都可能被使用者或攻擊者恢復, 特別是root過的device.
請確認沒有使用"file.delete()"去刪除必要的資料, 建議改用覆寫後再刪除等安全清除方式。
請看這個影片: https://www.youtube.com/watch?v=tGw1fxUD-uY""" + "||" + \
u"""Detected File.delete() co-located with a sensitive keyword (password/token/secret, etc.) in the same method.
Anything you delete can be recovered by users or attackers, especially rooted devices.
Please make sure you do not use "file.delete()" to delete the necessary data; consider securely
overwriting the file before deletion instead.
See this video: https://www.youtube.com/watch?v=tGw1fxUD-uY""",
            [u"FileDelete", u"DataRemanence"])

        for r in results_063[:5]:
            writer.write(u"{0}->{1}".format(
                r.get('class', ''), r.get('method', '')
            ))

    # ------------------------------------------------------------------------
    # [lab_064] - Check if app check for installing from Google Play
    
    find_method_params = {
        'classname': 'Landroid/content/pm/PackageManager;',
        'methodname': 'getInstallerPackageName'
    }
    result = get_androguard('/find_method', find_method_params)
    #path_getInstallerPackageName = filteringEngine.filter_list_of_paths(
    #    d, path_getInstallerPackageName)

    if result:
        writer.startWriter(
        "HACKER_INSTALL_SOURCE_CHECK", LEVEL_NOTICE, u"[AS-lab064] APP安裝來源檢查",
        u"這APP有檢查APK安裝來源(e.g. from Google Play, from Amazon, etc.)." + "||" + u"This app has check APK installation source(e.g. from Google Play, from Amazon, etc.)",
        ["Hacker"])
        # writer.show_Paths(d, path_getInstallerPackageName)
    else:
        writer.startWriter("HACKER_INSTALL_SOURCE_CHECK", LEVEL_INFO,
                           u"[AS-lab064] APP安裝來源檢查", u"這APP沒有檢查APK安裝來源",
                           ["Hacker"])

    # ------------------------------------------------------------------------
    # [lab_065] - WebView advanced configuration audit (migrated to androguard_server)
    # 補 lab_034 未涵蓋的 setter: setAllowFileAccess / setMixedContentMode /
    # setWebContentsDebuggingEnabled (與 lab_034 零重疊)
    result_lab065 = get_androguard('/lab_065')

    if result_lab065 and isinstance(result_lab065, dict) and result_lab065.get('has_finding'):
        warning_065 = result_lab065.get('warning', [])

        writer.startWriter(
            "LAB_065_WEBVIEW_ADVANCED_CONFIG", LEVEL_WARNING,
            u"[AS-lab065][MAS-4.1.2.3.7][MASVS-PLATFORM-2][CWE-200] WebView 進階配置檢查",
            u"檢查 lab_034 未涵蓋的 WebView 危險設定 (與 lab_034 零重疊): "
            u"setAllowFileAccess(true) -> WebView 可載入 file:// URL,配合 file 載入入口可存取本地檔案"
            u"(注意: 與 lab_034 的 setAllowFileAccessFromFileURLs 是不同 API); "
            u"setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW) -> HTTPS 頁面可載入 HTTP 子資源,MITM 風險; "
            u"setWebContentsDebuggingEnabled(true) -> 遠端 Chrome DevTools 除錯,release 版必須關閉。"
            u"靜態分析無法判斷 release/debug build,故均標 WARNING 供人工確認。"
            u" Ref: https://developer.android.com/reference/android/webkit/WebSettings"
            + "||" +
            u"Checks dangerous WebView settings not covered by lab_034 (zero overlap): "
            u"setAllowFileAccess(true) -> WebView can load file:// URLs (different API from "
            u"setAllowFileAccessFromFileURLs in lab_034); "
            u"setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW) -> HTTPS page can load HTTP sub-resources (MITM); "
            u"setWebContentsDebuggingEnabled(true) -> remote Chrome DevTools debugging, must be off in release. "
            u"Static analysis cannot tell release vs debug, so all are WARNING for manual review."
            u" Ref: https://developer.android.com/reference/android/webkit/WebSettings",
            ["WebView", "Config"])

        if warning_065:
            writer.write(u"[WARNING: %d]" % len(warning_065))
            for f in warning_065:
                cls = f.get('class', '')
                if cls.startswith('L') and cls.endswith(';'):
                    cls = cls[1:-1].replace('/', '.')
                writer.write(u"  %s.%s()  api=%s  reason=%s" % (
                    cls, f.get('method', ''), f.get('api', ''), f.get('reason', '')))

    # ------------------------------------------------------------------------
    # [lab_066] - Adb Backup check

    if a.is_adb_backup_enabled():
        writer.startWriter(
            "ALLOW_BACKUP", LEVEL_NOTICE,
            u"[AS-lab066][MAST-4.2.7][][CVE-2013-5112][CVE-2014-7952] AndroidManifest Adb Backup 檢查",
            u"""ADB Backup對這app來說是允許的(預設: ENABLED). ADB Backup是一個很好的工具對於備份資料而且. 如果這個app是開放的, 人們利用它可以複製你的私密檔案 (Prerequisite: 1.解鎖螢幕 2.進入開發者模式). 私密資料可能包括 lifetime access token, 使用者名稱或密碼, etc.
ADB Backup的安全例子:
1.http://www.securityfocus.com/archive/1/530288/30/0/threaded
2.http://blog.c22.cc/advisories/cve-2013-5112-evernote-android-insecure-storage-of-pin-data-bypass-of-pin-protection/
3.http://nelenkov.blogspot.co.uk/2012/06/unpacking-android-backups.html
Reference: http://developer.android.com/guide/topics/manifest/application-element.html#allowbackup
"""+ "||" +u"""ADB Backup is allowed for this app (default: ENABLED). ADB Backup is a great tool for backing up data and. If the app is open, people can use it to copy your private files (Prerequisite: 1. unlock the screen 2. enter developer mode). Private data may include lifetime access token, user name or password, etc.
ADB Backup security example:
1. http://www.securityfocus.com/archive/1/530288/30/0/threaded
2. http://blog.c22.cc/advisories/cve-2013-5112-evernote-android-insecure-storage-of-pin-data-bypass-of-pin-protection/
3. http://nelenkov.blogspot.co.uk/2012/06/unpacking-android-backups.html
Reference: http://developer.android.com/guide/topics/manifest/application-element.html#allowbackup
""")

    # ------------------------------------------------------------------------
    # [lab_067] - SSL Verification Fail (To check whether the code verifies the certificate)

    methods_X509TrustManager_list = get_method_ins_by_implement_interface_and_method_desc_dict(
        d, ["Ljavax/net/ssl/X509TrustManager;"], TYPE_COMPARE_ANY, [
            "getAcceptedIssuers()[Ljava/security/cert/X509Certificate;",
            "checkClientTrusted([Ljava/security/cert/X509Certificate; Ljava/lang/String;)V",
            "checkServerTrusted([Ljava/security/cert/X509Certificate; Ljava/lang/String;)V"
        ])

    list_X509Certificate_Critical_class = []
    list_X509Certificate_Warning_class = []

    for class_name, method_list in methods_X509TrustManager_list.items():
        ins_count = 0

        for method in method_list:
            for ins in method.get_instructions():
                ins_count = ins_count + 1
        
        # Critical
        if ins_count <= 4:
            list_X509Certificate_Critical_class.append(class_name)
        # Warning
        else:
            list_X509Certificate_Warning_class.append(class_name)

    if list_X509Certificate_Critical_class or list_X509Certificate_Warning_class:

        log_level = LEVEL_WARNING
        log_partial_prefix_msg = u"請確認這個app可以檢查SSL的證書是否仍然有效.如果不能正確的檢查，他可能會讓自我簽名、過期的或是不一樣的CN certificates的SSL連線."
        log_partial_prefix_msg_en = u"Please make sure the app can check if the SSL certificate is still valid. If it does not check correctly, it may allow SSL connections with self-signed, expired or different CN certificates."

        if list_X509Certificate_Critical_class:
            log_level = LEVEL_CRITICAL
            log_partial_prefix_msg = u"這個app沒有檢查SSL的證書是否仍然有效.他會讓自我簽名、過期的或是不一樣的CN certificates的SSL連線."
            log_partial_prefix_msg_en = u"This app does not check if the SSL certificate is still valid. It will allow SSL connections with self-signed, expired or different CN certificates."

        list_X509Certificate_merge_list = []
        list_X509Certificate_merge_list.extend(
            list_X509Certificate_Critical_class)
        list_X509Certificate_merge_list.extend(
            list_X509Certificate_Warning_class)

        dict_X509Certificate_class_name_to_caller_mapping = {}

        for method in d.get_methods():
            for i in method.get_instructions(
            ):  # method.get_instructions(): Instruction
                if i.get_op_value() == 0x22:  # 0x22 = "new-instance"
                    if i.get_string() in list_X509Certificate_merge_list:
                        referenced_class_name = i.get_string()
                        if referenced_class_name not in dict_X509Certificate_class_name_to_caller_mapping:
                            dict_X509Certificate_class_name_to_caller_mapping[
                                referenced_class_name] = []

                        dict_X509Certificate_class_name_to_caller_mapping[
                            referenced_class_name].append(method)

        writer.startWriter(
            "SSL_X509", log_level,
            u"[AS-lab067][OWASP-V5.1,V5.2,V5.3,V5.4][MAST-4.2.6][工-4.1.4.2.2, 4.1.4.2.3][CVE-2015-1816][M3] SSL證書的正確性檢查",
            log_partial_prefix_msg + u"""
這是一個嚴重的威脅會允許攻擊者在你不知道的狀況下使用中間人攻擊.
如果你在傳送使用者的帳號或密碼等等的敏感性資料，這是有可能會洩漏的.
參考:
(1)OWASP Mobile Top 10 doc: https://www.owasp.org/index.php/Mobile_Top_10_2014-M3
(2)Android Security book: http://goo.gl/BFb65r
原網址 https://books.google.com.tw/books?id=DuC64OoJSGQC&pg=PA79&lpg=PA79&dq=Android+HostnameVerifier+verify+true&source=bl&ots=CaIs9KbmNx&sig=aNoyDFc4BKRwartdS_3wqCoWtlc&hl=zh-TW&sa=X&ei=tK8iU7_9DIqpkQWT3ICoAw&ved=0CHEQ6AEwBw#v=onepage&q=Android%20HostnameVerifier%20verify%20true&f=false
(3) https://blog.csdn.net/SCHOLAR_II/article/details/107616324
這個弱點遠比Apple's "goto fail" 還要嚴重，弱點: http://goo.gl/eFlovw
請不要嘗試製造一個"X509Certificate" 並覆蓋 "checkClientTrusted", "checkServerTrusted" 和 "getAcceptedIssuers" 會沒有任何作用.
我們強烈建議你使用現存的 API 別嘗試自行製造X509Certificate class.
請修改或是移除有弱點的程式:
""" + "||" + log_partial_prefix_msg_en + """This is a serious threat that could allow an attacker to use a man-in-the-middle attack without your knowledge.
If you are sending sensitive information such as user accounts or passwords, it is possible that this could be compromised.
References:
(1)OWASP Mobile Top 10 doc: https://owasp.org/www-project-mobile-top-10/2016-risks/m3-insecure-communication
(2)Android Security book: http://goo.gl/BFb65r
Original URL https://books.google.com.tw/books?id=DuC64OoJSGQC&pg=PA79&lpg=PA79&dq=Android+HostnameVerifier+verify+true&source=bl&ots= CaIs9KbmNx&sig=aNoyDFc4BKRwartdS_3wqCoWtlc&hl=zh-TW&sa=X&ei=tK8iU7_9DIqpkQWT3ICoAw&ved=0CHEQ6AEwBw#v=onepage&q=Android% 20HostnameVerifier%20verify%20true&f=false
(3)https://blog.csdn.net/SCHOLAR_II/article/details/107616324
This weakness is far more serious than Apple's "goto fail", weakness: http://goo.gl/eFlovw
Please do not try to create a "X509Certificate" and override "checkClientTrusted", "checkServerTrusted" and "getAcceptedIssuers" it will have no effect.
We strongly recommend that you do not try to create your own X509Certificate class using the existing API.
Please modify or remove any weaknesses in the program:""", ["SSL_Security"])
        if list_X509Certificate_Critical_class:
            writer.write("[Confirm Vulnerable]")
            for name in list_X509Certificate_Critical_class:
                writer.write("=> " + name)
                if name in dict_X509Certificate_class_name_to_caller_mapping:
                    for used_method in dict_X509Certificate_class_name_to_caller_mapping[
                            name]:
                        writer.write("      -> used by: " + used_method.
                                     get_class_name() + "->" + used_method.
                                     get_name() + used_method.get_descriptor())

        if list_X509Certificate_Warning_class:
            writer.write("--------------------------------------------------")
            writer.write("[Maybe Vulnerable (Please manually confirm)]")
            for name in list_X509Certificate_Warning_class:
                writer.write("=> " + name)
                if name in dict_X509Certificate_class_name_to_caller_mapping:
                    for used_method in dict_X509Certificate_class_name_to_caller_mapping[
                            name]:
                        writer.write("      -> used by: " + used_method.
                                     get_class_name() + "->" + used_method.
                                     get_name() + used_method.get_descriptor())
                                    
    # ------------------------------------------------------------------------
    # [lab_068] - user identification is performed when using transaction resources
    # 實作：使用者使用Biometric API時，是否有實作 onAuthenticationError, onAuthenticationSucceeded, onAuthenticationFailed (no callback function)
    # Reference: https://android-developers.googleblog.com/2019/10/one-biometric-api-over-all-android.html

    # Check is Biometric API used
    path_has_biometric = vmx.get_tainted_packages(
    ).search_class_methods_exact_match('Landroidx/biometric/BiometricPrompt;', 'init', '(Landroidx/fragment/app/FragmentManager; Landroidx/biometric/BiometricViewModel; Ljava/util/concurrent/Executor; Landroidx/biometric/BiometricPrompt$AuthenticationCallback;)V')

    if path_has_biometric:
        onAuthenticationFailed = False
        onAuthenticationError = False
        onAuthenticationSucceeded = False
        methods_onAuthenticationFailed_list = []
        methods_onAuthenticationError_list = []
        methods_onAuthenticationSucceeded_list = []


        # public - onAuthenticationFailed()V
        path_onAuthenticationFailed = vmx.get_tainted_packages(
        ).search_methods_exact_match(
            "onAuthenticationFailed",
            "()V"
        )
        path_onAuthenticationFailed = filteringEngine.filter_list_of_paths(
        d, path_onAuthenticationFailed)

        datas = analysis.get_source_Paths(d, path_onAuthenticationFailed)
        for data in datas:
            src_class_name = data["src_class_name"]
            src_method_name = data["src_method_name"]
            src_descriptor = data["src_descriptor"]

            if src_method_name == "onAuthenticationFailed":
                onAuthenticationFailed = True
                ins_count = 0
                method = d.get_specific_class_method_descriptor(src_class_name, src_method_name, src_descriptor)
                for ins in method.get_instructions():
                    ins_count = ins_count + 1
                
                # 複寫後完全對該 function 沒有任何操作
                if ins_count == 0:
                    methods_onAuthenticationFailed_list.append(method)

        # public - onAuthenticationError()V
        path_onAuthenticationError = vmx.get_tainted_packages(
        ).search_methods_exact_match(
            "onAuthenticationError",
            "(I Ljava/lang/CharSequence;)V"
        )

        path_onAuthenticationError = filteringEngine.filter_list_of_paths(
        d, path_onAuthenticationError)

        datas = analysis.get_source_Paths(d, path_onAuthenticationError)
        for data in datas:
            src_class_name = data["src_class_name"]
            src_method_name = data["src_method_name"]
            src_descriptor = data["src_descriptor"]

            if src_method_name == "onAuthenticationError":
                onAuthenticationError = True
                ins_count = 0
                method = d.get_specific_class_method_descriptor(src_class_name, src_method_name, src_descriptor)
                #print(method)
                for ins in method.get_instructions():
                    ins_count = ins_count + 1
                
                # 複寫後完全對該 function 沒有任何操作
                if ins_count == 0:
                    methods_onAuthenticationError_list.append(method)

        # public - onAuthenticationSucceeded()V
        path_onAuthenticationSucceeded = vmx.get_tainted_packages(
        ).search_methods_exact_match(
            "onAuthenticationSucceeded",
            "(Landroidx/biometric/BiometricPrompt$AuthenticationResult;)V"
        )

        path_onAuthenticationSucceeded = filteringEngine.filter_list_of_paths(
        d, path_onAuthenticationSucceeded)

        datas = analysis.get_source_Paths(d, path_onAuthenticationSucceeded)
        for data in datas:
            src_class_name = data["src_class_name"]
            src_method_name = data["src_method_name"]
            src_descriptor = data["src_descriptor"]

            if src_method_name == "onAuthenticationSucceeded":
                onAuthenticationSucceeded = True
                ins_count = 0
                method = d.get_specific_class_method_descriptor(src_class_name, src_method_name, src_descriptor)
                
                for ins in method.get_instructions():
                    ins_count = ins_count + 1
                
                # 複寫後完全對該 function 沒有任何操作
                if ins_count == 0:
                    methods_onAuthenticationSucceeded_list.append(method)
        
        
        check_implementation = False
        # 未覆寫 onAuthenticationError, onAuthenticationSucceeded, onAuthenticationFailed
        if (onAuthenticationFailed == False or onAuthenticationError == False or onAuthenticationSucceeded == False):
            log_level = "Critical"
            log_partial_prefix_msg = u"使用了生物識別 API，但未覆寫 onAuthenticationFailed, onAuthenticationError, onAuthenticationSucceeded。"
            log_partial_prefix_msg_en = "Biometric API is used, but not implement onAuthenticationFailed, onAuthenticationError, onAuthenticationSucceeded"
            
        # 有複寫 onAuthenticationError, onAuthenticationSucceeded, onAuthenticationFailed ，但是沒有任何操作
        elif len(methods_onAuthenticationFailed_list) >= 0 or len(methods_onAuthenticationError_list) >= 0 or len(methods_onAuthenticationSucceeded_list) >= 0:
            check_implementation = True
            log_level = "Warning"
            log_partial_prefix_msg = u"使用了生物識別 API，有覆寫 onAuthenticationFailed, onAuthenticationError, onAuthenticationSucceeded，但沒有任何操作。"
            log_partial_prefix_msg_en = "Biometric API is used, already implement onAuthenticationFailed, onAuthenticationError, onAuthenticationSucceeded but no any instructions"

        
        writer.startWriter(
            "USER_Identification", log_level,
            u"[AS-lab068][OWASP-V4.7,4.10,5.5][M4] 是否正確實作使用者生物辨識身分鑑別 (Biometric API)",
            log_partial_prefix_msg + u"""
使用者身分鑑別是一種確保使用者身分的方法，透過使用者身分鑑別，可以確保使用者的身分，並且確保使用者的資料不會被其他人存取。
使用者身分鑑別的方法有很多種，例如：密碼、生物識別、指紋、人臉辨識等等。
在 Android 中，可以使用 Biometric API 來實作生物識別，但是要注意，如果沒有正確實作，則會有安全性的問題。
依據工業局 4.1.2.3.1 項目，請確認在使用交易資源前，是否有正確實作生物辨識身分鑑別
參考: 
(1) https://android-developers.googleblog.com/2019/10/one-biometric-api-over-all-android.html
(2) https://developer.android.com/training/sign-in/biometric-auth
""" + "||" + log_partial_prefix_msg_en + """
User identity authentication is a method to ensure the user's identity. Through user identity authentication, the user's identity can be ensured, and the user's information can not be accessed by others.
There are many methods for user identification, such as passwords, biometrics, fingerprints, face recognition, and so on.
In Android, you can use the Biometric API to implement biometrics, but be aware that if it is not implemented correctly, there will be security issues.
According to 4.1.2.3.1, please confirm whether the biometric identification is correctly performed before using the transaction resources
refer to: 
(1) https://android-developers.googleblog.com/2019/10/one-biometric-api-over-all-android.html
(2) https://developer.android.com/training/sign-in/biometric-auth
""", ["user_Identification"])

        if check_implementation:
            for method in methods_onAuthenticationFailed_list:
                writer.write(method, u"未實做 onAuthenticationFailed。", "Not implement onAuthenticationFailed.")
            for method in methods_onAuthenticationError_list:
                writer.write(method, u"未實做 onAuthenticationError。", "Not implement onAuthenticationError.")
            for method in methods_onAuthenticationSucceeded_list:
                writer.write(method, u"未實做 onAuthenticationSucceeded。", "Not implement onAuthenticationSucceeded.")
    else:
        writer.startWriter(
            "USER_Identification", "INFO",
            u"[AS-lab068][OWASP-V4.7,4.10,5.5][M4] 是否正確實作使用者生物辨識身分鑑別 (Biometric API)",
            u"未偵測到使用 Biometric API" + "||" + "No Biometric API used", ["user_Identification"])
    

    #----------------------------------------------------------------
    
    # [lab_069] Detect Overlay Attack prevention (Tapjacking)
    # Check if filterTouchesWhenObscured is set to true in AndroidManifest.xml
    # This attribute prevents overlay attacks by ignoring touch events when the view is obscured

    lab069Result = get_androguard('/lab_069')

    if lab069Result and lab069Result.get('has_finding') == True:
        print("Lab69 pass")
    else:
        print("Have Overlay Attack issue by the lab69")
        # 可能存在 Overlay Attack (Tapjacking) 風險
        writer.startWriter(
            "OVERLAY_ATTACK_PREVENTION", LEVEL_WARNING,
            u"[AS-lab069][MAS V4.0 4.1.5.1.3] Overlay Attack (Tapjacking) 防護檢測",
            u"此 app 未偵測到設定 filterTouchesWhenObscured=\"true\"，可能存在 Overlay Attack (Tapjacking) 風險。建議在敏感 UI 元件中設定此屬性。\n 參考: https://developer.android.com/privacy-and-security/risks/tapjacking?hl=zh-tw#risk_full_occlusion " + "||" + \
            u"This app does not have filterTouchesWhenObscured=\"true\" set. It may be vulnerable to Overlay Attack (Tapjacking). Consider setting this attribute on sensitive UI elements.\n refer to: https://developer.android.com/privacy-and-security/risks/tapjacking#risk_full_occlusion",
            ["Overlay", "Tapjacking", "Security"])
        writer.write(u"filterTouchesWhenObscured=\"true\" not found ! ")
    
    

    #----------------------------------------------------------------

    # [lab_070] 4.1.2.1.2 使用者拒絕蒐集敏感性資料之權利 — Runtime Permission 機制檢測
    # 靜態驗證：有 dangerous permission 宣告時，是否實作 runtime request 及拒絕處理

    lab070Result = get_androguard('/lab_070')

    if lab070Result:
        verdict = lab070Result.get('verdict', '')
        dangerous_perms = lab070Result.get('dangerous_permissions', [])
        perms_str = u", ".join(dangerous_perms) if dangerous_perms else u"(none)"

        if verdict == 'FAIL':
            writer.startWriter(
                "SENSITIVE_DATA_REFUSAL_MECHANISM", LEVEL_CRITICAL,
                u"[AS-lab070][MAS V4.0 4.1.2.1.2] 使用者拒絕蒐集敏感性資料之權利 — Runtime Permission 機制未實作",
                u"App 宣告了 dangerous permission（" + perms_str + u"），但靜態掃描未發現任何 Runtime Permission Request 呼叫（requestPermissions / registerForActivityResult）。"
                u"使用者無法行使拒絕權利，違反 4.1.2.1.2。\n"
                u"建議實作 Android Runtime Permission 機制，並正確處理使用者拒絕的情境。\n"
                u"參考: https://developer.android.com/training/permissions/requesting" + "||" +
                u"App declares dangerous permission(s) (" + perms_str + u") but no Runtime Permission Request call was found (requestPermissions / registerForActivityResult). "
                u"Users cannot exercise the right to refuse, violating 4.1.2.1.2.\n"
                u"Implement Android Runtime Permission mechanism and handle the denied scenario properly.\n"
                u"Refer to: https://developer.android.com/training/permissions/requesting",
                ["Permission", "Privacy", "RuntimePermission"])
            writer.write(u"Declared dangerous permissions: " + perms_str)

        elif verdict == 'WARNING':
            writer.startWriter(
                "SENSITIVE_DATA_REFUSAL_MECHANISM", LEVEL_WARNING,
                u"[AS-lab070][MAS V4.0 4.1.2.1.2] 使用者拒絕蒐集敏感性資料之權利 — 未確認拒絕情境處理",
                u"App 已實作 Runtime Permission Request，但靜態掃描未在 onRequestPermissionsResult() 中發現明確的拒絕（DENIED）分支處理邏輯。"
                u"建議確認拒絕後 App 能合理降級運作，而非強制要求或 crash。需搭配動態測試驗證。\n"
                u"Declared dangerous permissions: " + perms_str + "||" +
                u"App implements Runtime Permission Request, but no explicit denied-branch logic was detected in onRequestPermissionsResult(). "
                u"Verify the app degrades gracefully after denial — dynamic testing required.\n"
                u"Declared dangerous permissions: " + perms_str,
                ["Permission", "Privacy", "RuntimePermission"])

        # verdict == 'PASS' or 'INFO': 符合或無需檢測，不寫入 finding
    else:
        print("Lab070: androguard server returned no result, skipping")
     # ------------------------------------------------------------------------
    # [lab_071] - Debug log calls (Log.d / Log.v) in release build
    result_lab071 = get_androguard('/lab_071')

    if result_lab071 and isinstance(result_lab071, dict):
        findings_071 = result_lab071.get('results', [])

        if findings_071:
            writer.startWriter(
                "LAB_071_DEBUG_LOG", LEVEL_NOTICE,
                u"[AS-lab071][4.1.2.3.16][MSTG-STORAGE-3] 系統日誌敏感資料洩漏檢查",
                u"偵測到 App 使用 Log.d() 或 Log.v() 輸出除錯資訊，Release 版本不應保留這些呼叫。"
                u" Ref: https://developer.android.com/privacy-and-security/risks/log-info-disclosure"
                + "||" +
                u"Debug log calls (Log.d / Log.v) detected. These should be removed before release."
                u" Ref: https://developer.android.com/privacy-and-security/risks/log-info-disclosure",
                ["Log", "Privacy"])
            for item in findings_071:
                writer.write(u"  {} -> {} [{}]".format(
                    item.get('class', ''),
                    item.get('method', ''),
                    item.get('log_api', '')))
    #-----------------------------------------------------------------------
     # [lab_072] - Keyboard Cache Protection Check
    result_lab072 = get_androguard('/lab_072')

    if result_lab072 and isinstance(result_lab072, dict):
        findings_072 = result_lab072.get('results', [])

        if findings_072:
            writer.startWriter(
                "LAB_072_KEYBOARD_CACHE", LEVEL_WARNING,
                u"[AS-lab072][4.1.2.3.11][MSTG-STORAGE-5] 鍵盤快取保護檢查",
                u"偵測到敏感輸入欄位未設定 inputType 鍵盤快取保護，鍵盤可能會學習並快取使用者輸入的敏感資料（密碼、PIN、CVV 等）。"
                u" Ref: https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0006/"
                 + "||" +
                u"Sensitive input fields detected without keyboard cache protection (inputType). "
                u"The keyboard IME may cache user input including passwords, PINs, and CVV numbers."
                u" Ref: https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0006/",
                ["Privacy", "Storage"])
            for item in findings_072:
                writer.write(u"  [{}] {} | hint='{}' id='{}' | {}".format(
                    item.get('severity', ''),
                    item.get('file', ''),
                    item.get('hint', ''),
                    item.get('id', ''),
                    item.get('description', '')))

    #----------------------------------------------------------------

    # [AS-lab073] - 4.1.2.3.14 — 備份資料不應存有敏感性資料
    result_lab073 = get_androguard('/lab_073')

    if result_lab073 and isinstance(result_lab073, dict):
        if result_lab073.get('has_finding', False):
            manifest   = result_lab073.get('manifest', {})
            api_calls  = result_lab073.get('storage_api_calls', [])
            api_count  = result_lab073.get('storage_api_count', 0)

            allow_backup   = manifest.get('allow_backup', 'not set')
            full_backup    = manifest.get('full_backup_content')
            data_extract   = manifest.get('data_extraction_rules')
            has_exclusion  = manifest.get('has_backup_exclusion', False)

            writer.startWriter(
                "LAB_073_BACKUP_SENSITIVE", LEVEL_NOTICE,
                u"[AS-lab073][4.1.2.3.14][MASVS-STORAGE-2] 備份資料敏感性資料保護檢查",
                u"偵測到 App 可能將敏感資料納入備份。android:allowBackup 為 true 或未設定，"
                u"且程式碼中存在敏感儲存 API 呼叫或未設定備份排除規則。"
                u" Ref: https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/"
                u" | https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0262/"
                + "||" +
                u"App may include sensitive data in backups. android:allowBackup is true or not set, "
                u"and sensitive storage API calls were found or no backup exclusion rules are configured."
                u" Ref: https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/"
                u" | https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0262/",
                ["Backup", "Privacy"])

            writer.write(u"[Manifest] allowBackup={}  fullBackupContent={}  dataExtractionRules={}  hasExclusionRules={}".format(
                allow_backup,
                full_backup  if full_backup  else "not set",
                data_extract if data_extract else "not set",
                has_exclusion))

            if api_calls:
                writer.write(u"[Sensitive Storage APIs] count={}".format(api_count))
                for item in api_calls:
                    writer.write(u"  {} -> {} [{}]".format(
                        item.get('class', ''),
                        item.get('method', ''),
                        item.get('api', '')))

    # ------------------------------------------------------------------------
    # [AS-lab074] - 4.1.2.3.8 — 敏感性資料應避免出現於程式碼
    result_lab074 = get_androguard('/lab_074')

    if result_lab074 and isinstance(result_lab074, dict):
        findings_074 = result_lab074.get('results', [])

        if findings_074:
            smali_findings = result_lab074.get('smali_findings', [])
            xml_findings   = result_lab074.get('xml_findings', [])

            writer.startWriter(
                "LAB_074_HARDCODED_SECRET", LEVEL_CRITICAL,
                u"[AS-lab074][4.1.2.3.8][MASVS-STORAGE-2] 程式碼中含有硬編碼敏感資料",
                u"在 App 的 smali bytecode 或 XML 資源檔中偵測到疑似硬編碼的敏感字串（API Key、密碼、Token 等）。"
                u"敏感資料不應直接寫在程式碼或資源檔中，應使用安全的金鑰管理機制。"
                u" Ref: https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/"
                u" | https://developer.android.com/privacy-and-security/risks/hardcoded-cryptographic-secrets"
                + "||" +
                u"Hardcoded sensitive data (API keys, passwords, tokens) detected in bytecode or XML resources. "
                u"Sensitive values must not be stored in source code or resource files. "
                u"Use a secure key management solution instead. "
                u"Ref: https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/"
                u" | https://developer.android.com/privacy-and-security/risks/hardcoded-cryptographic-secrets",
                ["Hardcoded", "Privacy"])

            if smali_findings:
                writer.write(u"[Smali Bytecode findings: {}]".format(len(smali_findings)))
                for item in smali_findings:
                    cls    = item.get('class', '').replace('L', '', 1).replace(';', '').replace('/', '.')
                    method = item.get('method', '')
                    val    = item.get('string', '')[:50]
                    reason = item.get('match_reason', '')
                    writer.write(u"  {}.{}() : \"{}\"  [{}]".format(cls, method, val, reason))

            if xml_findings:
                writer.write(u"[XML Resource findings: {}]".format(len(xml_findings)))
                for item in xml_findings:
                    name   = item.get('resource_name', '')
                    val    = item.get('value', '')[:50]
                    reason = item.get('match_reason', '')
                    writer.write(u"  name=\"{}\"  value=\"{}\"  [{}]".format(name, val, reason))

    # [lab_075] 4.1.2.3.10 — 敏感性資料應儲存於系統憑證儲存設施
    result_lab075 = get_androguard('/lab_075')

    if result_lab075 and isinstance(result_lab075, dict) and result_lab075.get('has_finding'):
        verdict_075    = result_lab075.get('verdict', 'WARNING')
        insecure_075   = result_lab075.get('insecure_list', [])
        no_keystore_075 = result_lab075.get('no_keystore', False)
        level_075      = LEVEL_CRITICAL if verdict_075 == 'CRITICAL' else LEVEL_NOTICE

        DISCLAIMER_ZH = (
            u"[!] 靜態分析限制：(1) 僅確認 KeyStore.getInstance() 參數，無法驗證金鑰保護參數是否正確設定。"
            u"(2) 第三方加密函式庫（如 Tink、EncryptedSharedPreferences）可能已內部使用 AndroidKeyStore，"
            u"從 smali 層不易辨識，可能產生誤判。(3) 建議搭配動態分析確認金鑰實際儲存位置及保護強度。"
            u" Ref: https://developer.android.com/training/articles/keystore"
            u" | https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0051/"
        )
        DISCLAIMER_EN = (
            u"[!] Static analysis limitations: (1) Only KeyStore.getInstance() arguments are verified; "
            u"key protection parameters (e.g. KeyGenParameterSpec) are not checked. "
            u"(2) Third-party libraries (e.g. Tink, EncryptedSharedPreferences) may internally use AndroidKeyStore "
            u"but are hard to identify at smali level, which may produce false positives. "
            u"(3) Dynamic analysis is recommended to confirm actual key storage and protection strength."
            u" Ref: https://developer.android.com/training/articles/keystore"
            u" | https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0051/"
        )

        if no_keystore_075:
            title_075 = (
                u"未偵測到任何 KeyStore API 呼叫，請人工確認敏感金鑰儲存方式。"
                + DISCLAIMER_ZH
                + u"||"
                + u"No KeyStore API call detected; manual review recommended for sensitive key storage. "
                + DISCLAIMER_EN
            )
        elif verdict_075 == 'CRITICAL':
            providers = u", ".join(sorted(set(i.get('provider', 'unknown') for i in insecure_075)))
            title_075 = (
                u"未使用 Android 系統憑證儲存設施(AndroidKeyStore)，"
                u"金鑰可能以不安全方式儲存 (provider: %s)。" % providers
                + DISCLAIMER_ZH
                + u"||"
                + u"Sensitive key not stored in AndroidKeyStore; insecure provider(s) detected: %s. " % providers
                + DISCLAIMER_EN
            )
        else:
            providers = u", ".join(sorted(set(i.get('provider', 'unknown') for i in insecure_075)))
            title_075 = (
                u"部分金鑰未使用 AndroidKeyStore，混用不安全的憑證儲存方式 (provider: %s)。" % providers
                + DISCLAIMER_ZH
                + u"||"
                + u"Mixed KeyStore usage detected; some keys use insecure provider(s): %s. " % providers
                + DISCLAIMER_EN
            )

        writer.startWriter(
            "LAB_075_KEYSTORE_SYSTEM_STORAGE", level_075,
            u"[AS-lab075][MAS-4.1.2.3.10][MASVS-STORAGE-1] 敏感性資料應儲存於系統憑證儲存設施",
            title_075,
            ["KeyStore", "Storage"]
        )

        for item in insecure_075:
            cls      = item.get('class', '').replace('L', '', 1).replace(';', '').replace('/', '.')
            method   = item.get('method', '')
            provider = item.get('provider', 'unknown')
            writer.write(u"  %s.%s()  [provider: %s]" % (cls, method, provider))

    # [lab_076] - Deep Link Security (manifest scheme / autoVerify / host)
    result_lab076 = get_androguard('/lab_076')

    if result_lab076 and isinstance(result_lab076, dict) and result_lab076.get('has_finding'):
        findings_076 = result_lab076.get('results', [])
        has_high_076 = any(
            sev == 'HIGH'
            for entry in findings_076
            for sev, _ in entry.get('risks', [])
        )
        level_076 = LEVEL_CRITICAL if has_high_076 else LEVEL_WARNING

        writer.startWriter(
            "LAB_076_DEEP_LINK_SECURITY", level_076,
            u"[AS-lab076][MASVS-PLATFORM-3][CWE-939] Deep Link 安全檢查",
            u"偵測到 Deep Link intent-filter 設定風險:"
            u"(1) HTTP scheme 易遭 MITM "
            u"(2) http(s) App Link 缺 autoVerify=\"true\",其他 App 可註冊同 host 攔截 "
            u"(3) 自訂 scheme 未限制 host,任何 App 可註冊同 scheme。"
            u" Ref: https://developer.android.com/privacy-and-security/risks/unsafe-use-of-deeplinks?hl=zh-tw"
            u" | https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-3/"
            + "||" +
            u"Deep link intent-filter risks detected: "
            u"(1) http scheme exposed to MITM "
            u"(2) http(s) App Link missing autoVerify=\"true\" — other apps may intercept "
            u"(3) Custom scheme without host restriction — scheme hijack possible."
            u" Ref: https://developer.android.com/privacy-and-security/risks/unsafe-use-of-deeplinks"
            u" | https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-3/",
            ["DeepLink", "IntentFilter"]
        )

        for e in findings_076:
            uri_str = "{}://{}".format(e.get('scheme', ''), e.get('host', '') or '*')
            for sev, msg in e.get('risks', []):
                writer.write(u"  [{}] {} -> {}  ({})".format(
                    sev, e.get('activity', ''), uri_str, msg))

    # [lab_077] - Deep Link Injection (source -> sink in same method, heuristic)
    result_lab077 = get_androguard('/lab_077')

    if result_lab077 and isinstance(result_lab077, dict) and result_lab077.get('has_finding'):
        findings_077 = result_lab077.get('results', [])

        writer.startWriter(
            "LAB_077_DEEP_LINK_INJECTION", LEVEL_CRITICAL,
            u"[AS-lab077][MASVS-PLATFORM-3][CWE-20] Deep Link Injection 檢查",
            u"在 Deep Link Activity 的 method 中,同時偵測到 deep link 參數來源"
            u"(getData / getQueryParameter / getPath 等) 與危險 sink"
            u"(WebView.loadUrl / Intent.parseUri / File / SQL / Runtime.exec)。"
            u"代表 Deep Link 帶入的 URI 參數可能未經驗證即流向敏感操作。"
            u"本檢查為「同 method 啟發式」,無 taint 追蹤,可能誤報,需人工確認資料流。"
            u" Ref: https://developer.android.com/privacy-and-security/risks/unsafe-use-of-deeplinks?hl=zh-tw"
            + "||" +
            u"In a deep link Activity method, a deep link source (getData / getQueryParameter / getPath etc.) "
            u"is detected together with a dangerous sink (WebView.loadUrl / Intent.parseUri / File / SQL / Runtime.exec). "
            u"A URI parameter from a deep link may flow unsanitized into a sensitive operation. "
            u"Same-method heuristic only — no taint tracking. Manual review required to confirm actual data flow."
            u" Ref: https://developer.android.com/privacy-and-security/risks/unsafe-use-of-deeplinks",
            ["DeepLink", "Injection"]
        )

        for f in findings_077:
            cls = f.get('class', '')
            if cls.startswith('L') and cls.endswith(';'):
                cls = cls[1:-1].replace('/', '.')
            writer.write(u"  [{}] {}.{}() -> {} ({})  sources: {}".format(
                f.get('severity', ''), cls, f.get('method', ''),
                f.get('sink', ''), f.get('risk', ''),
                ", ".join(f.get('sources', []))))

    # [lab_078] - 4.1.5.1.2 ZIP Path Traversal (ZipSlip) 檢查
    result_lab078 = get_androguard('/lab_078')

    if result_lab078 and isinstance(result_lab078, dict) and result_lab078.get('has_finding'):
        findings_078 = result_lab078.get('findings', [])

        writer.startWriter(
            "LAB_078_ZIP_PATH_TRAVERSAL", LEVEL_CRITICAL,
            u"[AS-lab078][MAS-4.1.5.1.2][MASVS-CODE-4][CWE-22] ZIP Path Traversal (ZipSlip) 漏洞檢查",
            u"偵測到 App 解壓縮 ZIP 檔案時,使用 ZipEntry.getName() 取得檔名後直接以 new File(...) 建立目標路徑,"
            u"未在同一 method 內呼叫 getCanonicalPath() 或檢查 \"..\" 路徑穿越字串。"
            u"惡意 ZIP 可包含 ../ 序列將檔案寫入 App 沙箱外的任意位置(甚至覆蓋 .so 函式庫造成 RCE)。"
            u"經典案例: Google Play Core CVE-2020-8913。"
            u"修補建議: 解壓前以 destDir.getCanonicalPath() 比對 outputFile.getCanonicalPath().startsWith(...)。"
            u" Ref: https://developer.android.com/privacy-and-security/risks/zip-path-traversal"
            + "||" +
            u"App extracts ZIP entries using ZipEntry.getName() and constructs new File(...) without validating "
            u"the resolved path against the target directory (no getCanonicalPath() check or \"..\" string check "
            u"detected in the same method). A malicious ZIP can use ../ sequences to write files outside the app "
            u"sandbox, potentially overwriting native libraries and achieving RCE. Reference case: Google Play "
            u"Core CVE-2020-8913. Mitigation: verify outputFile.getCanonicalPath().startsWith(destDir.getCanonicalPath())."
            u" Ref: https://developer.android.com/privacy-and-security/risks/zip-path-traversal",
            ["ZipSlip", "PathTraversal"]
        )

        for f in findings_078:
            cls = f.get('class', '')
            if cls.startswith('L') and cls.endswith(';'):
                cls = cls[1:-1].replace('/', '.')
            writer.write(u"  %s.%s()  [missing: %s]" % (
                cls, f.get('method', ''), f.get('missing_check', '')))

    #----------------------------------------------------------------
    # [Completed] - Must complete the last writer

    writer.completeWriter()
    writer.writeInf_ForceNoPrint("vector_total_count",
                                 writer.get_total_vector_count())

    #----------------------------------------------------------------
    # End of Checking

    # StopWatch
    now = datetime.now()
    stopwatch_total_elapsed_time = now - stopwatch_start
    stopwatch_analyze_time = now - analyze_start
    stopwatch_loading_vm = analyze_start - stopwatch_start

    writer.writeInf_ForceNoPrint("time_total",
                                 stopwatch_total_elapsed_time.total_seconds())
    writer.writeInf_ForceNoPrint("time_analyze",
                                 stopwatch_analyze_time.total_seconds())
    writer.writeInf_ForceNoPrint("time_loading_vm",
                                 stopwatch_loading_vm.total_seconds())

    writer.update_analyze_status("success")
    writer.writeInf_ForceNoPrint("time_finish_analyze", datetime.utcnow())


def __persist_db(writer, args):

    # starting_dvm
    # starting_androbugs

    #  if platform.system().lower() == "windows":
    #  db_config_file = os.path.join(
    #  os.path.dirname(sys.executable), 'maldroid-db.cfg')
    #  else:
    #  db_config_file = os.path.join(os.path.dirname(
    #  os.path.abspath(__file__)), 'maldroid-db.cfg')

    #  if not os.path.isfile(db_config_file):
    #  print("[ERROR] AndroBugs Framework DB config file not found: " + db_config_file)
    #  traceback.print_exc()

    configParser = SafeConfigParser()
    # Fix the config file path
    config_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config')
    config_path = os.path.join(config_dir, 'Dy-db.cfg')
    configParser.read(config_path)

    MongoDB_Hostname = configParser.get('DB_Config', 'MongoDB_Hostname')
    MongoDB_Port = configParser.getint('DB_Config', 'MongoDB_Port')
    MongoDB_Database = configParser.get('DB_Config', 'MongoDB_Database')

    Collection_Analyze_Result = configParser.get('DB_Collections',
                                                 'Collection_Analyze_Result')
    Collection_Analyze_Success_Results = configParser.get(
        'DB_Collections', 'Collection_Analyze_Success_Results')
    Collection_Analyze_Success_Results_FastSearch = configParser.get(
        'DB_Collections', 'Collection_Analyze_Success_Results_FastSearch')
    Collection_Analyze_Fail_Results = configParser.get(
        'DB_Collections', 'Collection_Analyze_Fail_Results')

    from pymongo import MongoClient
    client = MongoClient(MongoDB_Hostname, MongoDB_Port)
    db = client[MongoDB_Database]  # Name is case-sensitive

    analyze_status = writer.get_analyze_status()

    try:

        if analyze_status is not None:
            # You might not get Package name when in "starting_apk" stage

            # "details" will only be shown when success
            packed_analyzed_results = writer.get_packed_analyzed_results_for_mongodb(
            )
            # specifically designed for Massive Analysis
            packed_analyzed_results_fast_search = writer.get_search_enhanced_packed_analyzed_results_for_mongodb(
            )

            # Name is case-sensitive
            collection_AppInfo = db[Collection_Analyze_Result]
            # collection_AppInfo.insert(packed_analyzed_results)

            global DYLANPACKAGENAME, inserted_app_id
            inserted_app_id = collection_AppInfo.insert(
                packed_analyzed_results, check_keys=False)
            # print("* Result page: http://127.0.0.1/report/" + str(inserted_app_id) + ' ' + DYLANPACKAGENAME)
            with open('/out/result.txt', 'a') as dylan:
                dylan.write("./report/" + str(inserted_app_id) + ' ' +
                            DYLANPACKAGENAME + '\n')

            if analyze_status == "success":  # save analyze result only when successful
                collection_AnalyzeSuccessResults = db[Collection_Analyze_Success_Results]
                collection_AnalyzeSuccessResults.insert(packed_analyzed_results)

                collection_AnalyzeSuccessResultsFastSearch = db[Collection_Analyze_Success_Results_FastSearch]
                collection_AnalyzeSuccessResultsFastSearch.insert(packed_analyzed_results_fast_search)

        if analyze_status == "fail":
            # Name is case-sensitive
            collection_AnalyzeExceptions = db[Collection_Analyze_Fail_Results]
            collection_AnalyzeExceptions.insert(writer.getInf())

    # pymongo.errors.BulkWriteError, pymongo.errors.CollectionInvalid, pymongo.errors.CursorNotFound, pymongo.errors.DocumentTooLarge, pymongo.errors.DuplicateKeyError, pymongo.errors.InvalidOperation
    except Exception as err:
        try:
            writer.update_analyze_status("fail")
            writer.writeInf_ForceNoPrint("analyze_error_detail_traceback",
                                         traceback.format_exc())

            writer.writeInf_ForceNoPrint("analyze_error_type_expected", False)
            writer.writeInf_ForceNoPrint("analyze_error_time",
                                         datetime.utcnow())
            writer.writeInf_ForceNoPrint("analyze_error_id", str(type(err)))
            writer.writeInf_ForceNoPrint("analyze_error_message", str(err))

            packed_analyzed_results = writer.getInf()
            """
				http://stackoverflow.com/questions/5713218/best-method-to-delete-an-item-from-a-dict
				There's also the minor point that .pop will be slightly slower than the del since it'll translate to a function call rather than a primitive.
				packed_analyzed_results.pop("details", None)	#remove the "details" tag, if the key is not found => return "None"
			"""
            if "details" in packed_analyzed_results:  # remove "details" result to prevent the issue is generating by the this item
                del packed_analyzed_results["details"]

            # Name is case-sensitive
            collection_AnalyzeExceptions = db[Collection_Analyze_Fail_Results]
            collection_AnalyzeExceptions.insert(packed_analyzed_results)
        except:
            if DEBUG:
                print("[Error on writing Exception to MongoDB]")
                traceback.print_exc()


def _make_signature_hash(writer, first_key, first_default):
    # signature = hash(first_key(default) + "-" + file_sha256(default="") + "-" + timestamp + "-" + random8)
    tmp_original = (writer.getInf(first_key, first_default) + "-" +
                    writer.getInf("file_sha256", "sha256") + "-" +
                    str(time.time()) + "-" +
                    str(random.randrange(10000000, 99999999)))
    return hashlib.sha512(tmp_original).hexdigest()


def get_hash_scanning(writer):
    return _make_signature_hash(writer, "package_name", "pkg")


def get_hash_exception(writer):
    return _make_signature_hash(writer, "analyze_error_id", "err")


# def __persist_file(writer, args):

#     package_name = writer.getInf("package_name")
#     signature_unique_analyze = writer.getInf("signature_unique_analyze")

#     if package_name and signature_unique_analyze:
#         return writer.save_result_to_file(
#             os.path.join(
#                 args.report_output_dir,
#                 package_name + "_" + signature_unique_analyze + ".txt"), args)
#     else:
#         print("\"package_name\" or \"signature_unique_analyze\" not exist.")
#         return False


def main():

    args = parseArgument()

    writer = Writer(excluded_labs=EXCLUDED_LABS)

    try:

        # Print Title
        # writer.writePlainInf("""*************************************************************************
        #**   AndroBugs Framework - Android App Security Vulnerability Scanner  **
        #**                            version: 1.0.0                           **
        #**     author: Yu-Cheng Lin (@AndroBugs, http://www.AndroBugs.com)     **
        #**               contact: androbugs.framework@gmail.com                **
        #*************************************************************************""")

        __analyze(writer, args)

        analyze_signature = get_hash_scanning(writer)
        # For uniquely distinguish the analysis report
        writer.writeInf_ForceNoPrint("signature_unique_analyze",
                                     analyze_signature)
        writer.append_to_file_io_information_output_list(
            "Analyze Signature: " + analyze_signature)
        writer.append_to_file_io_information_output_list(
            "------------------------------------------------------------------------------------------------"
        )
        
    except ExpectedException as err_expected:

        writer.update_analyze_status("fail")

        writer.writeInf_ForceNoPrint("analyze_error_type_expected", True)
        writer.writeInf_ForceNoPrint("analyze_error_time", datetime.utcnow())
        writer.writeInf_ForceNoPrint("analyze_error_id",
                                     err_expected.get_err_id())
        writer.writeInf_ForceNoPrint("analyze_error_message",
                                     err_expected.get_err_message())

        writer.writeInf_ForceNoPrint(
            "signature_unique_analyze", get_hash_scanning(
                writer))  # For uniquely distinguish the analysis report
        writer.writeInf_ForceNoPrint("signature_unique_exception",
                                     get_hash_exception(writer))

        if DEBUG:
            print(err_expected)

    # This may happen in the "a = apk.APK(apk_Path)"
    except BadZipfile as zip_err:

        writer.update_analyze_status("fail")

        # Save the fail message to db
        writer.writeInf_ForceNoPrint("analyze_error_detail_traceback",
                                     traceback.format_exc())

        writer.writeInf_ForceNoPrint("analyze_error_type_expected", True)
        writer.writeInf_ForceNoPrint("analyze_error_time", datetime.utcnow())
        writer.writeInf_ForceNoPrint("analyze_error_id",
                                     "fail_to_unzip_apk_file")
        writer.writeInf_ForceNoPrint("analyze_error_message", str(zip_err))

        writer.writeInf_ForceNoPrint(
            "signature_unique_analyze", get_hash_scanning(
                writer))  # For uniquely distinguish the analysis report
        writer.writeInf_ForceNoPrint("signature_unique_exception",
                                     get_hash_exception(writer))

        if DEBUG:
            print("[Unzip Error]")
            traceback.print_exc()

    except Exception as err:

        writer.update_analyze_status("fail")

        # Save the fail message to db
        writer.writeInf_ForceNoPrint("analyze_error_detail_traceback",
                                     traceback.format_exc())

        writer.writeInf_ForceNoPrint("analyze_error_type_expected", False)
        writer.writeInf_ForceNoPrint("analyze_error_time", datetime.utcnow())
        writer.writeInf_ForceNoPrint("analyze_error_id", str(type(err)))
        writer.writeInf_ForceNoPrint("analyze_error_message", str(err))

        writer.writeInf_ForceNoPrint(
            "signature_unique_analyze", get_hash_scanning(
                writer))  # For uniquely distinguish the analysis report
        writer.writeInf_ForceNoPrint("signature_unique_exception",
                                     get_hash_exception(writer))

        if DEBUG:
            traceback.print_exc()

    # Save to the DB (optional, only if Dy-db.cfg exists)
    try:
        __persist_db(writer, args)
    except Exception as e:
        if DEBUG:
            print("[INFO] DB persistence skipped: %s" % e)
    # Save to the File
    # __persist_file(writer, args)
    # show json
    merge_dict_tw, merge_dict_en = writer.get_json()
    # generate pdf
    generate_pdf_state = writer.generate_pdf(args, merge_dict_tw, merge_dict_en)
    # Write state to the Frida dir (not CWD='/') so webapp.py's monitor reads it
    _frida_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(_frida_dir, "maldroid.state"), 'w') as f:
        f.write("success" if generate_pdf_state else "fail")
    print("generate_pdf_state: " + str(generate_pdf_state))


if __name__ == "__main__":
    main()
"""
	Packages do not check:
		java
		android
		com.google
		org.apache
		org.json
		org.xml
"""