import os
import re
import time
import zipfile
import json
import subprocess
import base64
from flask import Flask, request, jsonify, send_file
from androguard.misc import AnalyzeAPK

a = None
d = None
dx = None
apk_path = None
TMP_DIR = "Reports/"

class FilteringEngine:
    """
    Placeholder for filtering engine to check if class name is excluded.
    Replace with actual implementation based on your exclusion logic.
    """
    @staticmethod
    def is_class_name_not_in_exclusion(class_name):
        # Placeholder: Assume all classes are included unless specified
        excluded_packages = ["Landroid/", "Landroidx/", "Lcom/google/", "Lkotlin/", "Lkotlinx/", "Lorg/"]  # exclusions packages
        
        # Debug: Print the class name being checked
        #print(f"DEBUG: Checking class: {class_name}")
        
        for pkg in excluded_packages:
            if class_name.startswith(pkg):
                #print(f"DEBUG: Class {class_name} starts with {pkg} - EXCLUDED")
                return False
        
        #print(f"DEBUG: Class {class_name} - INCLUDED")
        return True


def check_server_health(port: int, timeout: int = 300):
    """
    Check if the androguard server is ready by checking for a flag file.
    """
    start_time = time.time()
    flag_file = f"androguard_ready_{port}.flag"
    
    while time.time() - start_time < timeout:
        if os.path.exists(flag_file):
            # Delete the flag file after finding it
            try:
                os.remove(flag_file)
                print(f"[Androguard] Cleaned up flag file: {flag_file}")
            except OSError as e:
                print(f"[Warning] Failed to delete flag file {flag_file}: {e}")
            return True, "Server is ready (flag file found and cleaned up)"
        time.sleep(0.1)  # Check every 100ms
    
    return False, f"Server did not become ready within {timeout} seconds"

def run_androguard_server(port: int, initial_apk_path: str = None):

    app = Flask(__name__)

    global a, d, dx, apk_path
    apk_path = initial_apk_path
    if apk_path:
        print('androguard_server: Analyzing the APK...')
        a, d, dx = AnalyzeAPK(apk_path)
        print('androguard_server: Analysis complete')
    
    # Debug: Print the types of returned objects
    # print(f'DEBUG: Type of a: {type(a)}')
    # print(f'DEBUG: Type of d: {type(d)}')
    # print(f'DEBUG: Type of dx: {type(dx)}')
    
    # If d is a list (multiple DEX files), we need to handle it differently
    if isinstance(d, list):
        print(f'DEBUG: d is a list with {len(d)} items')
        for i, dex in enumerate(d):
            print(f'DEBUG: d[{i}] type: {type(dex)}')
    else:
        print(f'DEBUG: d is not a list, it is: {type(d)}')
    
    # Create a flag file to indicate analysis is complete
    flag_file = f"androguard_ready_{port}.flag"
    with open(flag_file, 'w') as f:
        f.write("ready")
    print(f'androguard_server: Created ready flag file: {flag_file}')

    #find specific method calls by instructions
    def find_method_calls(dx, target_class=None, target_method=None):
        found_calls = []
        
        for class_name, cls_value in dx.classes.items():
            for method in cls_value.get_methods():
                method_analysis = method.get_method()
                if method_analysis and hasattr(method_analysis, 'get_instructions'):
                    instructions = list(method_analysis.get_instructions())
                    
                    for i, instruction in enumerate(instructions):
                        ins_output = instruction.get_output()
                        if target_class in ins_output and target_method in ins_output:
                            found_calls.append({
                                'class': class_name,
                                'method': method.name,
                                'instructions': instructions,
                                'call_index': i
                            })
                
        return found_calls

    """
        Generator: iterate over all app methods, excluding system/library classes.
        Yields: (class_name, method, method_analysis)
    """
    def iter_app_methods(dx):
        for class_name, cls_value in dx.classes.items():
            if not FilteringEngine.is_class_name_not_in_exclusion(class_name):
                continue
            for method in cls_value.get_methods():
                m = method.get_method()
                if m:
                    yield class_name, method, m

    def resolve_activity_name(package_name, activity_name):
        """
        Resolve a short activity name from AndroidManifest to its full class name.
        Handles three formats:
          '.MyActivity'        -> 'com.example.app.MyActivity'
          'MyActivity'         -> 'com.example.app.MyActivity'
          'com.other.Activity' -> 'com.other.Activity'  (unchanged)
        """
        if activity_name.startswith('.'):
            return package_name + activity_name
        elif '.' not in activity_name:
            return package_name + '.' + activity_name
        return activity_name
    
    def find_so_files(a, *names):
        """
        Check which SO library filenames exist in the APK.
        Returns a set of found SO names.
        Example: find_so_files(a, 'libexec.so', 'libexecmain.so')
        """
        all_files = a.get_files()
        return {name for name in names if any(name in f for f in all_files)}

    #----------------------------------------------------------------

    @app.route('/load_apk', methods=['POST'])
    def load_apk():
        global a, d, dx, apk_path
        if 'file' not in request.files:
            return jsonify({"error": "No file part"}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No selected file"}), 400

        save_path = os.path.join("./uploads", file.filename)
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        file.save(save_path)
        apk_path = save_path

        try:
            a, d, dx = AnalyzeAPK(apk_path)
        except Exception as e:
            a, d, dx = None, None, None
            return jsonify({"error": f"Failed to analyze APK: {str(e)}"}), 500

        flag_file = "androguard_ready.flag"
        with open(flag_file, 'w') as f:
            f.write("ready")

        return jsonify({"message": f"APK loaded and analyzed: {file.filename}"}), 200

    @app.route('/run_maldroid', methods=['POST'])
    def run_maldroid_endpoint():
        global apk_path

        if not apk_path or not os.path.exists(apk_path):
            return jsonify({
                "error": "No APK loaded or invalid path",
                "apk_path": apk_path
            }), 400

        try:
            maldroid_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "maldroid_main.py")
            raw_fname = os.path.basename(apk_path)
            b64_fname = base64.b64encode(raw_fname.encode('utf-8')).decode('ascii')
            cmd = ["python2", maldroid_path, "-s", "-v", "-f", apk_path, "-n", b64_fname, "-u", "root"]

            print(f"[DEBUG] Running command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            print(f"[DEBUG] Return code: {result.returncode}")
            print(f"[DEBUG] STDOUT:\n{result.stdout}")
            print(f"[DEBUG] STDERR:\n{result.stderr}")

            if result.returncode != 0:
                return jsonify({
                    "error": "Maldroid analysis failed",
                    "stderr": result.stderr,
                    "returncode": result.returncode
                }), 500

            return jsonify({
                "message": "Maldroid analysis completed successfully",
                "stderr": result.stderr
            }), 200

        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            print(f"[ERROR] Exception in run_maldroid:\n{tb}")
            return jsonify({"error": str(e), "traceback": tb}), 500

    @app.route('/get_json', methods=['GET'])
    def get_json():
        try:
            file_hash = request.args.get("hash")
            if not file_hash:
                return jsonify({"error": "No hash parameter provided"}), 400

            lang = request.args.get("lang", "en")
            base_dir = os.path.dirname(os.path.abspath(__file__))

            if lang in ("zh", "zh-TW"):
                candidate_paths = [
                    os.path.join("./Reports", f"{file_hash}_static_zh.json"),
                    os.path.join(base_dir, "Reports", f"{file_hash}_static_zh.json"),
                    os.path.join("/app/Frida/maldroid/Reports", f"{file_hash}_static_zh.json"),
                    os.path.join("/app/Frida/Reports", f"{file_hash}_static_zh.json"),
                    os.path.join("/app/Frida", "test_zh.json"),
                    os.path.join(base_dir, "..", "test_zh.json"),
                    "./test_zh.json",
                    "/test_zh.json"
                ]
            else:
                filename = f"{file_hash}_static.json"
                candidate_paths = [
                    os.path.join("./Reports", filename),
                    os.path.join(base_dir, "Reports", filename),
                    os.path.join("/app/Frida/maldroid/Reports", filename),
                    os.path.join("/app/Frida/Reports", filename),
                    os.path.join("./Reports", f"{file_hash}.json"),
                    os.path.join("/app/Frida", "test.json"),
                    os.path.join(base_dir, "..", "test.json"),
                    "./test.json",
                    "/test.json",
                    os.path.join("/app/Frida", "test_zh.json"),
                    os.path.join(base_dir, "..", "test_zh.json"),
                    "./test_zh.json",
                    "/test_zh.json"
                ]

            file_path = None
            for p in candidate_paths:
                if os.path.exists(p):
                    file_path = p
                    break

            if not file_path:
                return jsonify({"error": "File not found", "attempted": candidate_paths}), 404

            with open(file_path, "r") as f:
                content = json.load(f)

            return jsonify(content), 200

        except Exception as e:
            import traceback
            print(traceback.format_exc())
            return jsonify({"error": f"Failed to read JSON: {str(e)}"}), 500

    @app.route('/androguard/lab16', methods=['GET'])
    def get_apk_lab16():
        with zipfile.ZipFile(apk_path, 'r') as zip_ref:
            all_files = zip_ref.namelist()
            match_files = [f for f in all_files if f.endswith('classes.dex')]
            if not match_files:
                return jsonify({"count": 0, "message": "No classes.dex file found in the APK"}), 200
            else:
                return jsonify({"count": len(match_files), "message": f"Found {len(match_files)} classes.dex file(s) in the APK"}), 200

    #----------------------------------------------------------------



    #----------------------------------------------------------------

    @app.route('/androguard/find_method', methods=['GET'])
    def find_method():
        classname = request.args.get('classname')
        methodname = request.args.get('methodname')

        print("find_method")
        
        if not classname or not methodname:
            return jsonify({"error": "Missing parameters"}), 400
        
        methods = list(dx.find_methods(classname=classname, methodname=methodname))
        print("methods: ", methods)
        
        if methods:
            response = {"method_found": True}
            return jsonify(response), 200
        else:
            response = {"method_found": False}
            return jsonify(response), 200
        # input("Stop!")  # Commented out to prevent server hanging
        # for method in methods:
        #     print("Method:", method.name)
        #     print("Descriptor:", method.descriptor)
        #     method_analysis = method.get_method()
        #     print('type of method_analysis', type(method_analysis))
        #     print('method_analysis: ', method_analysis)

        #     # print_methods_attributes(method)
        #     print(method.get_xref_from())
        #     print(method.get_xref_to())
        #     print(method.is_android_api())
        #     print(method.is_external())
    

    @app.route('/androguard/strings', methods=['GET'])
    def get_apk_strings():
        """
        Get all strings from the APK.

        :return: List of all strings
        """
        try:
            # Get all strings from the APK using dx (VMAnalysis)
            strings = []
            
            # Use dx.get_strings_analysis() which returns a dictionary of StringAnalysis objects
            if hasattr(dx, 'get_strings_analysis'):
                strings_analysis = dx.get_strings_analysis()
                print(f"DEBUG: Got strings_analysis: {type(strings_analysis)}")
                
                # Convert StringAnalysis objects to string values and filter readable strings
                if isinstance(strings_analysis, dict):
                    all_strings = list(strings_analysis.keys())
                    print(f"DEBUG: Extracted {len(all_strings)} total strings from strings_analysis")
                    
                    # Filter out non-readable strings
                    for string in all_strings:
                        # Skip empty strings
                        if not string or string.strip() == "":
                            continue
                        
                        # Skip strings with too many control characters
                        control_chars = sum(1 for c in string if ord(c) < 32 and c not in '\n\r\t')
                        if control_chars > len(string) * 0.3:  # More than 30% control chars
                            continue
                        
                        # Skip strings that are too short (likely not meaningful)
                        if len(string.strip()) < 3:
                            continue
                        
                        # Skip strings that are mostly special characters
                        special_chars = sum(1 for c in string if not c.isalnum() and not c.isspace() and c not in '.-_/@:')
                        if special_chars > len(string) * 0.8:  # More than 80% special chars
                            continue
                        
                        strings.append(string)
                    
                    print(f"DEBUG: Filtered to {len(strings)} readable strings")
                else:
                    print(f"DEBUG: strings_analysis is not a dict: {type(strings_analysis)}")
            else:
                print(f"DEBUG: dx does not have get_strings_analysis method")
            
            # Convert to list format for JSON serialization
            string_list = list(strings) if strings else []
            
            return jsonify({
                "strings": string_list,
                "count": len(string_list)
            }), 200
            
        except Exception as e:
            return jsonify({
                "error": f"Failed to get strings: {str(e)}"
            }), 500


    @app.route('/androguard/files', methods=['GET'])
    def get_apk_files():
        """
        Get all files from the APK.
        """
        try: 
            # Get all files from the APK
            files = a.get_files()
            
            # Convert to list format for JSON serialization
            file_list = list(files) if files else []
            
            return jsonify({
                "files": file_list,
                "count": len(file_list)
            }), 200
            
        except Exception as e:
            return jsonify({
                "error": f"Failed to get files: {str(e)}"
            }), 500

    @app.route('/androguard/search_packages', methods=['GET'])
    def search_packages():
        """
        Simple endpoint to get package names from APK classes.
        """
        try:
            packages = set()
            
            # Extract package names from class names
            for class_name in dx.classes.keys():
                if class_name.startswith('L') and class_name.endswith(';'):
                    # Remove L prefix and ; suffix, then split by /
                    parts = class_name[1:-1].split('/')
                    if len(parts) > 1:
                        # Get package name (everything except the last part which is the class name)
                        package = '/'.join(parts[:-1])
                        packages.add(package)
            
            # Convert to list and sort
            package_list = sorted(list(packages))
            
            return jsonify({
                "packages": package_list,
                "count": len(package_list)
            }), 200
            
        except Exception as e:
            return jsonify({
                "error": f"Failed to get packages: {str(e)}"
            }), 500

    @app.route('/androguard/classes', methods=['GET'])
    def get_all_classes():
        """
        Get all class names from the APK.
        """
        try:
            classes = list(dx.classes.keys())
            
            return jsonify({
                "classes": classes,
                "count": len(classes)
            }), 200
            
        except Exception as e:
            return jsonify({
                "error": f"Failed to get classes: {str(e)}"
            }), 500

    @app.route('/androguard/search', methods=['GET'])
    def simple_search():
        """Search for strings in APK methods"""
        search_string = request.args.get('q', '')
        if not search_string:
            return jsonify({"error": "Need 'q' parameter"}), 400
        
        results = []
        for class_name, cls_value in dx.classes.items():
            if not FilteringEngine.is_class_name_not_in_exclusion(class_name):
                continue
            
            for method in cls_value.get_methods():
                try:
                    # Get method analysis object
                    method_analysis = method.get_method()
                    if method_analysis is None:
                        continue
                    
                    # Get instructions from method analysis
                    instructions = method_analysis.get_instructions()
                    if instructions is None:
                        continue
                    
                    for instruction in instructions:
                        if instruction.get_op_value() in [0x1A, 0x1B]:
                            string_value = instruction.get_string()
                            if search_string.lower() in string_value.lower():
                                results.append({
                                    "class": method.class_name,
                                    "method": method.name,
                                    "string": string_value
                                })
                except Exception as e:
                    # Skip methods that can't be analyzed
                    continue
        
        return jsonify({"results": results, "count": len(results)})
    

#-----------------------------------------------------------------

# Detect LABS

    @app.route('/androguard/lab02', methods=['GET'])
    def detect_security_methods():
        #input("Stop! From androguard_server.py LAB_002 ----------- Solving threading issue")
        """
        LAB_002: Detect security-related methods in the APK using regex patterns.

        :return: List of security-related MethodAnalysis objects
        """
        verbose = request.args.get('verbose', 'false').lower() == 'true'
        
        # Regular expressions for filtering methods
        regexGerneralRestricted = ".*(config|setting|constant).*"
        regexSecurityRestricted = ".*(encrypt|decrypt|encod|decod|aes|sha1|sha256|sha512|md5).*"
        prog = re.compile(regexGerneralRestricted, re.I)
        prog_sec = re.compile(regexSecurityRestricted, re.I)

        # Initialize list for security-related methods
        security_methods = []

        for class_name, method, _ in iter_app_methods(dx):
                method_name = method.name
                method_class_name = class_name  # MethodClassAnalysis has no .class_name; use loop var
                descriptor = method.descriptor

                if prog.match(method_name) or prog_sec.match(method_name):
                    if verbose:
                        print(f"Detected security-related method: {method_class_name}->{method_name}{descriptor}")

                    if (method_name != 'onConfigurationChanged' or
                            descriptor != '(Landroid/content/res/Configuration;)V'):
                        if verbose:
                            print(f"Class: {method_class_name}, Should include: True")
                        security_methods.append({
                            "class_name": method_class_name,
                            "method_name": method_name,
                        })
                          
        return jsonify({
            "results": security_methods,
            "count": len(security_methods),
            "has_finding": len(security_methods) > 0
        }), 200

    @app.route('/androguard/permissions', methods=['GET'])
    def get_apk_permissions():
        """
        Get all permissions declared in the APK.

        :return: List of all permissions
        """
        try:
            # Get all permissions from the APK
            permissions = a.get_permissions()
            
            # Convert to list format for JSON serialization
            permission_list = list(permissions) if permissions else []
            
            return jsonify({
                "permissions": permission_list,
                "count": len(permission_list)
            }), 200
            
        except Exception as e:
            return jsonify({
                "error": f"Failed to get permissions: {str(e)}"
            }), 500

 

    #----------------------------------------------------------------


    @app.route('/androguard/lab03', methods=['GET'])
    def detect_security_classes():
        """
        LAB_003: Detect security-related classes in the APK using regex patterns.

        :return: List of security-related class names
        """
        verbose = request.args.get('verbose', 'false').lower() == 'true'
        
        # Regular expressions for filtering classes (same as in maldroid_main.py)
        regexGerneralRestricted = ".*(config|setting|constant).*"
        regexSecurityRestricted = ".*(encrypt|decrypt|encod|decod|aes|sha1|sha256|sha512|md5).*"
        prog = re.compile(regexGerneralRestricted, re.I)
        prog_sec = re.compile(regexSecurityRestricted, re.I)

        # Initialize list for security-related classes
        security_classes = []

        # Iterate through all classes
        for class_name, cls_value in dx.classes.items():
            # Check if class name matches restricted patterns
            if prog.match(class_name) or prog_sec.match(class_name):
                if verbose:
                    print(f"Detected security-related class: {class_name}")
                
                # Check if class should be included (not in exclusion list)
                should_include = FilteringEngine.is_class_name_not_in_exclusion(class_name)
                if verbose:
                    print(f"Class: {class_name}, Should include: {should_include}")
                
                if should_include:
                    # Convert class object to serializable format
                    class_info = {
                        "class_name": class_name,
                    }
                    security_classes.append(class_info)
                          
        return jsonify({
            "results": security_classes,
            "count": len(security_classes),
            "has_finding": len(security_classes) > 0
        }), 200

    #----------------------------------------------------------------
    # CVE-2023-4863 libwebp.so  BuildHuffmanTable Heap OverFlow
    @app.route('/androguard/lab_016', methods=['GET'])
    def detect_lab_016():
        """
        CVE-2023-4863: Detect vulnerable libwebp native libraries in the APK.
        Scans .so files for vulnerable strings (WebPCopyPlane, WebPCopyPixels, VP8LBuildHuffmanTable)
        and checks if the patched string (VP8LHuffmanTablesAllocate) is absent.
        If vulnerable strings are found but the safe string is missing, the library is affected.
        """
        results = []
        vulnerable_strings = [b'WebPCopyPlane', b'WebPCopyPixels', b'VP8LBuildHuffmanTable']
        safe_string = b'VP8LHuffmanTablesAllocate'

        try:
            all_files = a.get_files()
            so_files = [f for f in all_files if f.endswith('.so')]

            for so_file in so_files:
                try:
                    file_data = a.get_file(so_file)
                    if not file_data:
                        continue

                    # Check for vulnerable strings
                    matched = [s.decode() for s in vulnerable_strings if s in file_data]
                    # Check for safe (patched) string
                    has_safe = safe_string in file_data

                    if matched and not has_safe:
                        results.append({
                            "file": so_file,
                            "matched_strings": matched,
                            "patched": False,
                            "status": "VULNERABLE"
                        })
                    elif matched and has_safe:
                        results.append({
                            "file": so_file,
                            "matched_strings": matched,
                            "patched": True,
                            "status": "PATCHED"
                        })
                except Exception as e:
                    print(f"Error reading {so_file}: {e}")
                    continue

        except Exception as e:
            return jsonify({
                "error": f"Failed to scan native libraries: {str(e)}",
                "results": []
            }), 500

        vulnerable_count = sum(1 for r in results if r["status"] == "VULNERABLE")

        return jsonify({
            "results": results,
            "so_files_scanned": len(so_files) if 'so_files' in dir() else 0,
            "vulnerable_count": vulnerable_count,
            "has_vulnerability": vulnerable_count > 0,
            "lab_id": "lab_016",
            "cve": "CVE-2023-4863",
            "description": "libwebp VP8LBuildHuffmanTable Heap Overflow detection"
        }), 200
    
    # 不當對 FileProvider 揭露目錄
    @app.route('/androguard/lab_018', methods=['GET'])
    def detect_lab_018():
        """LAB_018: Detect improper FileProvider configuration (OWASP MASVS-STORAGE)"""
        results = []

        try:
            # 檢查 AndroidManifest 是否有 FileProvider
            manifest_xml = a.get_android_manifest_xml()
            has_fileprovider = False

            for provider in manifest_xml.findall('.//provider'):
                android_name = provider.get('{http://schemas.android.com/apk/res/android}name', '')
                if 'FileProvider' in android_name:
                    has_fileprovider = True
                    break

            if not has_fileprovider:
                return jsonify({"has_vulnerability": False, "message": "No FileProvider found"}), 200

            # 掃描 res/xml/ 下的設定檔
            all_files = a.get_files()
            xml_files = [f for f in all_files if f.startswith('res/xml/') and f.endswith('.xml')]

            print("[DEBUG lab_018] Total files in APK: {}".format(len(all_files)))
            print("[DEBUG lab_018] XML files found in res/xml/: {}".format(xml_files))

            for xml_file in xml_files:
                file_data = a.get_file(xml_file)
                if not file_data:
                    continue

                # Binary AXML still contains readable strings
                # Search for tag and attribute patterns in the binary data
                content_str = file_data.decode('utf-8', errors='ignore')

                print("[DEBUG lab_018] Checking file: {}".format(xml_file))

                # 檢查核心安全問題
                # In binary AXML, tag names and attributes are still readable as strings
                # 1. CRITICAL: root-path 暴露整個根目錄
                if 'root-path' in content_str or 'root_path' in content_str:
                    results.append({
                        "file": xml_file,
                        "issue": "root-path detected - exposes device root directory",
                        "severity": "CRITICAL",
                        "description": "The root-path tag exposes the entire device root directory (/), allowing access to all files on the device"
                    })
                    print("[DEBUG lab_018] Found root-path in {}".format(xml_file))

                # 2. HIGH: 廣泛路徑分享 - 檢查是否有 "." 作為路徑值
                # Look for common broad path indicators
                if 'all_files' in content_str or 'all_cache' in content_str:
                    results.append({
                        "file": xml_file,
                        "issue": "Broad path sharing detected (path='.' or path='')",
                        "severity": "HIGH",
                        "description": "Using '.' or empty path exposes the entire directory, allowing access to all files"
                    })
                    print("[DEBUG lab_018] Found broad path sharing in {}".format(xml_file))

                # 3. MEDIUM: external-path 可能暴露敏感資料
                if 'external-path' in content_str or 'external_path' in content_str or 'external_data' in content_str:
                    results.append({
                        "file": xml_file,
                        "issue": "external-path detected - may expose sensitive data",
                        "severity": "MEDIUM",
                        "description": "external-path may expose sensitive data outside app container in external storage"
                    })
                    print("[DEBUG lab_018] Found external-path in {}".format(xml_file))

            return jsonify({
                "has_vulnerability": len(results) > 0,
                "results": results,
                "count": len(results)
            }), 200

        except Exception as e:
            return jsonify({"error": str(e), "has_vulnerability": False}), 500

    @app.route('/androguard/lab23/some_other_api', methods=['GET'])
    def some_other_api_lab23():
        response = {"message": "This is some other API"}
        return jsonify(response), 200


    @app.route('/androguard/lab_27', methods=['GET'])
    def detect_screen_capture_prevention():
        """
        Detect screen capture prevention by finding setFlags calls and checking for FLAG_SECURE (0x2000) before it.
        """
        
        def check_for_0x2000_flag(instructions, call_index):
            for j in range(max(0, call_index-10), call_index):
                if j < len(instructions):
                    ins = instructions[j]
                    ins_name = ins.get_name()
                    ins_output = ins.get_output()
                    
                    if ins_name in ['const/16', 'const', 'const/4', 'const/high16']:
                        if '0x2000' in ins_output or '8192' in ins_output:
                            return True
            return False
        
        results = []
        
        # Find setFlags calls
        found_calls = find_method_calls(dx, target_class="Landroid/view/Window", target_method="setFlags")
        
        for call in found_calls:
            if check_for_0x2000_flag(call['instructions'], call['call_index']):
                results.append({
                    'flag_value': '0x2000',
                    'class_name': call['class'],
                    'method_name': call['method']
                })
        
        return jsonify({
            "results": results,
            "count": len(results)
        })
    @app.route('/androguard/lab_28', methods=['GET'])
    def detect_runtime_exec():
        """
        Detect Runtime.exec() and ProcessBuilder() calls in app-owned code.
        Extracts the previous const-string (within 5 instructions) as the command
        argument and categorizes each finding by severity:
          CRITICAL - no const-string found -> command argument is dynamic
                     (Command Injection / RCE risk)
          INFO     - const-string matches a known root-detection keyword
                     (su / which su / busybox / getprop ro.build.tags / id)
                     -> likely legitimate root detection, not an exploit
          WARNING  - const-string present but not a root-detection keyword
                     -> hardcoded command, manual review recommended
        """
        RUNTIME_EXEC_TOKEN  = "Ljava/lang/Runtime;->exec("
        PROCESS_BUILDER_CLS = "Ljava/lang/ProcessBuilder;"
        INVOKE_OPS          = {0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78}
        NEW_INSTANCE_OP     = 0x22
        CONST_STRING_OPS    = {0x1A, 0x1B}

        ROOT_DETECTION_KEYWORDS = (
            "su", "which su", "busybox", "magisk",
            "getprop ro.build.tags", "getprop ro.debuggable", "getprop ro.secure",
            "/system/xbin/su", "/system/bin/su", "/sbin/su",
            "id", "uname",
        )

        def categorize(cmd):
            if cmd is None:
                return "CRITICAL", "dynamic_command"
            low = cmd.lower().strip()
            for kw in ROOT_DETECTION_KEYWORDS:
                if kw == low or kw in low.split():
                    return "INFO", "root_detection"
                if kw in low and len(low) <= len(kw) + 16:
                    return "INFO", "root_detection"
            return "WARNING", "hardcoded_command"

        findings = []

        for class_name, method_analysis, method in iter_app_methods(dx):
            try:
                instructions = list(method.get_instructions())
            except Exception:
                continue

            method_name = method.get_name()

            for idx, ins in enumerate(instructions):
                try:
                    op = ins.get_op_value()

                    is_runtime_exec    = False
                    is_process_builder = False

                    if op in INVOKE_OPS:
                        out = ins.get_output() if hasattr(ins, 'get_output') else ''
                        if RUNTIME_EXEC_TOKEN in out:
                            is_runtime_exec = True
                    elif op == NEW_INSTANCE_OP:
                        out = ins.get_output() if hasattr(ins, 'get_output') else ''
                        if PROCESS_BUILDER_CLS in out:
                            is_process_builder = True

                    if not (is_runtime_exec or is_process_builder):
                        continue

                    cmd = None
                    for back in range(1, min(6, idx + 1)):
                        prev = instructions[idx - back]
                        if prev.get_op_value() in CONST_STRING_OPS:
                            cmd = prev.get_string()
                            break

                    severity, reason = categorize(cmd)

                    findings.append({
                        "class":    class_name,
                        "method":   method_name,
                        "api":      "Runtime.exec" if is_runtime_exec else "ProcessBuilder",
                        "command":  cmd if cmd is not None else "<dynamic>",
                        "severity": severity,
                        "reason":   reason,
                    })
                except Exception:
                    continue

        critical = [f for f in findings if f["severity"] == "CRITICAL"]
        warning  = [f for f in findings if f["severity"] == "WARNING"]
        info     = [f for f in findings if f["severity"] == "INFO"]

        if critical:
            verdict = "CRITICAL"
        elif warning:
            verdict = "WARNING"
        elif info:
            verdict = "INFO"
        else:
            verdict = "PASS"

        return jsonify({
            "verdict":     verdict,
            "has_finding": len(findings) > 0,
            "findings":    findings,
            "critical":    critical,
            "warning":     warning,
            "info":        info,
            "count":       len(findings),
            "lab_id":      "lab_028",
            # backward-compat field for legacy client expecting 'results'
            "results":     findings,
        }), 200

    @app.route('/androguard/lab031', methods=['GET'])
    def detect_lab_031():
        """ Find Landroid/net/SSLCertificateSocketFactory getInsecure """
        results = []
        found_calls = find_method_calls(dx, target_class="Landroid/net/SSLCertificateSocketFactory", target_method="getInsecure")
        for call in found_calls:
            results.append({
                'class_name': call['class'],
                'method_name': call['method']
            })
        
        return jsonify({
            "results": results,
            "count": len(results)
        })

    # Check Certificate Pinning
    @app.route('/androguard/lab035', methods=['GET'])
    def detect_lab_035():
        """
        LAB_035: Detect certificate pinning implementation in the APK.
        """
        results = []
        try:
            # --- 1.Network Security Config Inspection ---
            all_files = a.get_files()
            # serach -> res/xml Documents
            xml_candidates = [f for f in all_files if f.startswith('res/xml/') and f.endswith('.xml')]

            for xml_file in xml_candidates:
                try:
                    file_data = a.get_file(xml_file)
                    # handle decode error
                    if not file_data: continue

                    content = file_data.decode('utf-8', errors='ignore')

                    # Seach <pin-set> Key Workds
                    if '<pin-set' in content:
                        results.append({
                            "type": "Network Security Config",
                            "file": xml_file,
                            "detection_method": "XML pin-set configuration",
                            "status": "DETECTED"
                        })
                except Exception as e:
                    # Log error but continue scanning other files
                    print(f"Error analyzing XML {xml_file}: {e}")

            # --- 2.Code-Based Pinning Inspection (Refined) ---
            # Search Pinning Library features
            pinning_indicators = [
                # High Confidence Indicators
                ("Lokhttp3/CertificatePinner;", "OkHttp CertificatePinner"),
                ("Lokhttp3/CertificatePinner$Builder;", "OkHttp CertificatePinner Builder"),
                ("Lcom/datatheorem/android/trustkit/TrustKit;", "TrustKit Library")
            ]

            # Run CodeBased Pinning Inspection
            for target_class, description in pinning_indicators:
                found_calls = find_method_calls(dx, target_class=target_class, target_method="")

                if found_calls:
                    # Remove Dupliate logic
                    unique_classes = set()
                    for call in found_calls:
                        if FilteringEngine.is_class_name_not_in_exclusion(call['class']):
                            unique_classes.add(call['class'])

                    if unique_classes:
                        results.append({
                            "type": "Code-based Pinning",
                            "indicator": target_class,
                            "detection_method": description,
                            "found_in_classes": list(unique_classes),
                            "status": "DETECTED"
                        })

        except Exception as e:
            import traceback
            traceback.print_exc()
            return jsonify({
                "error": f"Failed to detect certificate pinning: {str(e)}",
                "results": [],
                "count": 0,
                "has_finding": False
            }), 500

        return jsonify({
            "results": results,
            "count": len(results),
            "has_finding": len(results) > 0,
            "lab_id": "lab_035",
            "description": "Certificate Pinning Detection"
        }), 200


    @app.route('/androguard/lab036', methods=['GET'])
    def detect_lab_036():
        """
        LAB_036: Detect Intent Redirection vulnerability
        檢測 Intent Redirection 漏洞

        檢測重點：
        1. Activity 在 AndroidManifest.xml 中設定為 exported=true
        2. 從 Intent 中取得 Parcelable extra (另一個 Intent)
        3. 直接使用這個 Intent 啟動元件，沒有驗證
        """
        results = []

        try:
            # Step 1: 從 AndroidManifest.xml 找出 exported=true 的 Activity
            manifest_xml = a.get_android_manifest_xml()
            exported_activities = []

            for activity in manifest_xml.findall('.//activity'):
                activity_name = activity.get('{http://schemas.android.com/apk/res/android}name', '')
                exported = activity.get('{http://schemas.android.com/apk/res/android}exported', '')
                has_intent_filter = len(activity.findall('.//intent-filter')) > 0

                # Check exported Activity
                # 條件：明確設定 exported="true" 或有 intent-filter（可能隱式 exported）
                if exported == 'true' or (has_intent_filter and exported != 'false'):
                    full_class_name = resolve_activity_name(a.get_package(), activity_name)

                    exported_activities.append({
                        'name': full_class_name,
                        'short_name': activity_name,
                        'exported': exported,
                        'has_intent_filter': has_intent_filter
                    })

            if not exported_activities:
                return jsonify({
                    "has_finding": False,
                    "message": "No exported Activity found",
                    "results": [],
                    "count": 0
                }), 200

            # Step 2: 掃描 exported Activity 的 smali 指令，找 Intent Redirection 模式
            #   Source: getIntent() + getParcelableExtra()
            #   Sink:   startActivity / startService / sendBroadcast / startActivityForResult
            vulnerable_methods = []
            exported_names = {a['name'] for a in exported_activities}
            INVOKE_OPS_036 = {0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78}

            for class_name, method, method_analysis in iter_app_methods(dx):
                    # 正確的 Dalvik 類名轉換: Lcom/example/LoginActivity; → com.example.LoginActivity
                    # (舊版 .replace('L','') 會刪除類名中所有大寫 L，例如 LoginActivity → oginActivity)
                    if class_name.startswith('L') and class_name.endswith(';'):
                        normalized = class_name[1:-1].replace('/', '.')
                    else:
                        normalized = class_name
                    if normalized not in exported_names:
                        continue

                    try:
                        instructions = list(method_analysis.get_instructions())
                    except Exception:
                        continue

                    has_get_intent       = False
                    has_get_parcelable   = False
                    has_start_activity   = False
                    has_start_service    = False
                    has_send_broadcast   = False
                    has_start_for_result = False

                    for ins in instructions:
                        try:
                            if ins.get_op_value() not in INVOKE_OPS_036:
                                continue
                            out = ins.get_output() if hasattr(ins, 'get_output') else ''
                            if '->getIntent(' in out:
                                has_get_intent = True
                            if '->getParcelableExtra(' in out:
                                has_get_parcelable = True
                            if '->startActivity(' in out:
                                has_start_activity = True
                            if '->startService(' in out:
                                has_start_service = True
                            if '->sendBroadcast(' in out:
                                has_send_broadcast = True
                            if '->startActivityForResult(' in out:
                                has_start_for_result = True
                        except Exception:
                            continue

                    if has_get_intent and has_get_parcelable:
                        if has_start_activity or has_start_service or has_send_broadcast or has_start_for_result:
                            dangerous_methods = []
                            if has_start_activity:
                                dangerous_methods.append('startActivity()')
                            if has_start_for_result:
                                dangerous_methods.append('startActivityForResult()')
                            if has_start_service:
                                dangerous_methods.append('startService()')
                            if has_send_broadcast:
                                dangerous_methods.append('sendBroadcast()')

                            vulnerable_methods.append({
                                "class": class_name,
                                "method": method.name,
                                "dangerous_methods": dangerous_methods,
                                "severity": "HIGH"
                            })

            # Step 3: Result
            if vulnerable_methods:
                results.append({
                    "issue": "Intent Redirection vulnerability detected",
                    "severity": "HIGH",
                    "description": "Exported Activity accepts Intent from external source via getParcelableExtra() and directly uses it to start components without validation. Attackers can launch private components and bypass access controls.",
                    "recommendation": "Always validate Intent received from getParcelableExtra(). Check component name against whitelist before calling startActivity/startService/sendBroadcast.",
                    "cwe": "CWE-927",
                    "affected_methods": vulnerable_methods
                })

            return jsonify({
                "has_finding": len(vulnerable_methods) > 0,
                "exported_activities": exported_activities,
                "results": results,
                "count": len(results)
            }), 200

        except Exception as e:
            return jsonify({
                "error": str(e),
                "has_finding": False,
                "count": 0
            }), 500

    @app.route('/androguard/lab038', methods=['GET'])
    def detect_lab_038():
        """ Find Ljava/lang/System loadLibrary """
        results = []
        found_calls = find_method_calls(dx, target_class="Ljava/lang/System", target_method="loadLibrary")
        for call in found_calls:
            results.append({
                'class_name': call['class'],
                'method_name': call['method']
            })
        return jsonify({
            "results": results,
            "count": len(results)
        })

    @app.route('/androguard/lab_039', methods=['GET'])
    def detect_framework_bangcle():
        """
        Detect framework bangcle by finding getACall calls.
        """

        results = []
        for name in find_so_files(a, 'libsecexe.so'):
            results.append({name: True})
        
        # Check ApplicationWrapper
        target_class = "com.secapk.wrapper.ApplicationWrapper"
        internal_name = "L" + target_class.replace(".", "/") + ";"
        if internal_name in dx.classes:
            results.append({
                "ApplicationWrapper": True
            })
        
        # Check getACall
        found_calls = find_method_calls(dx, target_class="Lcom/secapk/wrapper/ACall", target_method="getACall")
        if found_calls:
            results.append({
                "getACall": True
            })

        return jsonify({
            "results": results,
            "count": len(results)
        })

    @app.route('/androguard/lab_040', methods=['GET'])
    def detect_framework_ijiami():
        """
        Detect iJiami framework by finding specific files and methods.
        """
        results = []
        for name in find_so_files(a, 'libexec.so', 'libexecmain.so'):
            results.append({name: True})
        
        # Check NativeApplication class
        target_class = "Lcom/shell/NativeApplication;"
        if target_class in dx.classes:
            results.append({
                "NativeApplication": True
            })
        
        # Check load method
        found_calls = find_method_calls(dx, target_class="Lcom/shell/NativeApplication;", target_method="load")
        if found_calls:
            results.append({
                "load": True
            })
        
        return jsonify({
            "results": results,
            "count": len(results)
        })

    @app.route('/androguard/lab_041', methods=['GET'])
    def detect_framework_monodroid():
        """
        Detect MonoDroid framework by finding specific files and classes.
        """
        results = []
        for name in find_so_files(a, 'libmonodroid.so'):
            results.append({name: True})
        
        # Check mono.android.app.Application class
        target_class = "Lmono/android/app/Application;"
        if target_class in dx.classes:
            results.append({
                "mono_application": True
            })
        
        return jsonify({
            "results": results,
            "count": len(results)
        })

    @app.route('/androguard/lab_042', methods=['GET'])
    def detect_lab_042():
        """
        Unified packer / framework identification.
        Replaces standalone lab_039 (Bangcle), lab_040 (iJiami).

        Phase 1: Known packer identification (SO files + class signatures)
        Phase 2: Known plugin/hotfix/multidex framework identification
        """

        # ---- Phase 1: Known packer signatures (based on APKiD YARA rules) ----
        # Source: https://github.com/rednaga/APKiD/blob/master/apkid/rules/apk/packers.yara
        KNOWN_PACKERS = [
            # --- China mainstream ---
            {"name": "Bangcle",
             "so": ["libsecexe.so", "libsecmain.so", "libSecShell.so"],
             "classes": ["Lcom/secapk/wrapper/ApplicationWrapper;"],
             "prefixes": ["Lcom/secapk/"]},
            {"name": "Bangcle v2 (SecNeo)",
             "so": ["libDexHelper.so", "libdexjni.so", "libdatajar.so"],
             "classes": [],
             "prefixes": ["Lcom/secneo/apkwrapper/"]},
            {"name": "iJiami",
             "so": ["libexec.so", "libexecmain.so", "libijmDataEncryption.so"],
             "classes": ["Lcom/shell/NativeApplication;"],
             "prefixes": ["Lcom/shell/"]},
            {"name": "Tencent",
             "so": ["libshell.so", "libmobisecy.so", "libshella-", "libshellx-"],
             "classes": [],
             "prefixes": ["Lcom/tencent/StubShell/"]},
            {"name": "Qihoo 360",
             "so": ["libjiagu.so", "libprotectClass.so", "libapktoolplus_jiagu.so"],
             "classes": [],
             "prefixes": ["Lcom/qihoo/util/"]},
            {"name": "Baidu",
             "so": ["libbaiduprotect.so"],
             "classes": [],
             "prefixes": ["Lcom/baidu/protect/"]},
            {"name": "Alibaba",
             "so": ["libmobisec.so"],
             "classes": [],
             "prefixes": ["Lcom/alibaba/wireless/security/"]},
            {"name": "NetEase Yidun",
             "so": ["libnesec.so"],
             "classes": [],
             "prefixes": ["Lcom/netease/nis/"]},
            {"name": "Naga",
             "so": ["libedog.so", "libchaosvmp.so", "libxloader.so"],
             "classes": [],
             "prefixes": []},
            {"name": "Pangxie",
             "so": ["libnsecure.so"],
             "classes": [],
             "prefixes": []},
            {"name": "Tongfu Shield",
             "so": ["libegis.so"],
             "classes": [],
             "prefixes": []},
            {"name": "KiwiSec",
             "so": ["libkiwicrash.so", "libKwProtectSDK.so"],
             "classes": [],
             "prefixes": []},
            {"name": "DingXiang",
             "so": ["libsys_misc.so"],
             "classes": [],
             "prefixes": []},
            {"name": "Manxi Security",
             "so": ["libdSafeShell.so", "libmxacc.so", "libmanxi.so"],
             "classes": [],
             "prefixes": []},
            {"name": "Venustech",
             "so": ["libvenSec.so"],
             "classes": [],
             "prefixes": []},
            {"name": "Nesun",
             "so": ["libzprotect.so"],
             "classes": [],
             "prefixes": []},
            # --- International ---
            {"name": "AppGuard",
             "so": ["libAppGuard.so", "libcompatible.so"],
             "classes": [],
             "prefixes": []},
            {"name": "DxShield",
             "so": ["libdxbase.so"],
             "classes": [],
             "prefixes": []},
            {"name": "DexProtector",
             "so": ["dp.arm.so.dat", "dp.x86.so.dat"],
             "classes": [],
             "prefixes": []},
            {"name": "DexProtectX",
             "so": ["libVMDexShellx.so", "libdexshell.so"],
             "classes": [],
             "prefixes": []},
            {"name": "APKProtect",
             "so": ["libAPKProtect.so", "libapkprotect.so"],
             "classes": [],
             "prefixes": []},
            {"name": "Kiro",
             "so": ["libkiroro.so"],
             "classes": [],
             "prefixes": []},
            {"name": "Medusah (AppSolid)",
             "so": ["libmd.so"],
             "classes": [],
             "prefixes": []},
            {"name": "AppSealing",
             "so": ["libcovault.so"],
             "classes": [],
             "prefixes": []},
            {"name": "LIAPP",
             "so": [],
             "classes": [],
             "prefixes": ["Lcom/lockincomp/"]},
            {"name": "Approov",
             "so": ["libapproov.so"],
             "classes": [],
             "prefixes": []},
            {"name": "EpicVM",
             "so": ["libEpic_Vm.so"],
             "classes": [],
             "prefixes": []},
            {"name": "AppIron",
             "so": ["libAppIron-jni.so"],
             "classes": [],
             "prefixes": []},
            {"name": "Eversafe",
             "so": ["libeversafe.so"],
             "classes": [],
             "prefixes": []},
            {"name": "AppCamo",
             "so": ["libalib.so"],
             "classes": [],
             "prefixes": []},
            {"name": "NQ Shield",
             "so": ["libnqshield.so"],
             "classes": [],
             "prefixes": []},
            {"name": "Zimperium zShield",
             "so": [],
             "classes": [],
             "prefixes": ["Lcom/zimperium/"]},
            {"name": "Gpresto",
             "so": ["libATG_L.so"],
             "classes": [],
             "prefixes": []},
        ]

        # ---- Phase 2: Known non-packer frameworks ----
        KNOWN_FRAMEWORKS = [
            {"name": "AndroidX MultiDex", "type": "multidex",
             "prefixes": ["Landroidx/multidex/"]},
            {"name": "Support MultiDex",  "type": "multidex",
             "prefixes": ["Landroid/support/multidex/"]},
            {"name": "Tinker",  "type": "hotfix",
             "prefixes": ["Lcom/tencent/tinker/"]},
            {"name": "Sophix",  "type": "hotfix",
             "prefixes": ["Lcom/taobao/sophix/"]},
            {"name": "RePlugin", "type": "plugin",
             "prefixes": ["Lcom/qihoo360/replugin/"]},
            {"name": "VirtualAPK", "type": "plugin",
             "prefixes": ["Lcom/didi/virtualapk/"]},
            {"name": "Shadow", "type": "plugin",
             "prefixes": ["Lcom/tencent/shadow/"]},
        ]

        all_files       = a.get_files()
        all_class_names = list(dx.classes.keys())

        # ---- Phase 1 scan ----
        detected_packers = []
        for packer in KNOWN_PACKERS:
            evidence = []
            for so in packer["so"]:
                if any(so in f for f in all_files):
                    evidence.append("so:" + so)
            for cls in packer["classes"]:
                if cls in dx.classes:
                    evidence.append("class:" + cls)
            for prefix in packer["prefixes"]:
                if any(c.startswith(prefix) for c in all_class_names):
                    evidence.append("prefix:" + prefix)
            if evidence:
                detected_packers.append({"name": packer["name"], "evidence": evidence})

        # ---- Phase 2 scan ----
        detected_frameworks = []
        for fw in KNOWN_FRAMEWORKS:
            for prefix in fw["prefixes"]:
                if any(c.startswith(prefix) for c in all_class_names):
                    detected_frameworks.append({"name": fw["name"], "type": fw["type"]})
                    break

        verdict = "NOTICE" if detected_packers else "PASS"

        return jsonify({
            "verdict":     verdict,
            "has_finding": len(detected_packers) > 0,
            "packers":     detected_packers,
            "frameworks":  detected_frameworks,
            "count":       len(detected_packers),
            "lab_id":      "lab_042",
        }), 200

    @app.route('/androguard/lab_044', methods=['GET'])
    def detect_Dirty_Steam():
        """
        LAB_044: Detect Dirty Steam vulnerability
        檢測 Dirty Steam 路徑穿越攻擊漏洞

        檢測重點：
        1. AndroidManifest.xml 中有 ACTION_SEND/ACTION_SEND_MULTIPLE intent-filter
        2. 使用 ContentResolver.query() 查詢 _display_name
        3. 直接使用檔案名稱進行檔案操作，缺少驗證
        """
        results = []

        try:
            # Step 1: 檢查 AndroidManifest.xml 是否有接收外部檔案的 intent-filter
            manifest_xml = a.get_android_manifest_xml()
            vulnerable_activities = []

            for activity in manifest_xml.findall('.//activity'):
                activity_name = activity.get('{http://schemas.android.com/apk/res/android}name', '')

                for intent_filter in activity.findall('.//intent-filter'):
                    actions = intent_filter.findall('.//action')
                    for action in actions:
                        action_name = action.get('{http://schemas.android.com/apk/res/android}name', '')

                        # 檢查是否接收 ACTION_SEND 或 ACTION_SEND_MULTIPLE
                        if action_name in ['android.intent.action.SEND', 'android.intent.action.SEND_MULTIPLE']:
                            vulnerable_activities.append({
                                "activity": activity_name,
                                "action": action_name
                            })

            if not vulnerable_activities:
                return jsonify({
                    "has_finding": False,
                    "message": "No ACTION_SEND/SEND_MULTIPLE intent-filter found",
                    "results": [],
                    "count": 0
                }), 200

            # Step 2: smali 指令掃描，找 ContentResolver.query + _display_name + File 操作
            #   DISPLAY_NAME 是 compile-time constant，javac 會 inline 為 const-string "_display_name"
            content_resolver_usage = []
            file_operations = []
            INVOKE_OPS_044    = {0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78}
            CONST_OPS_044     = {0x1a, 0x1b}
            NEW_INSTANCE_044  = 0x22
            FILE_CLASSES_044  = ("Ljava/io/File;", "Ljava/io/FileOutputStream;", "Ljava/io/FileWriter;")

            for class_name, method, method_analysis in iter_app_methods(dx):
                    try:
                        instructions = list(method_analysis.get_instructions())
                    except Exception:
                        continue

                    has_display_name     = False
                    has_content_resolver = False
                    has_query            = False
                    has_file_operation   = False

                    for ins in instructions:
                        try:
                            op = ins.get_op_value()

                            if op in CONST_OPS_044:
                                s = ins.get_string()
                                if s and '_display_name' in s:
                                    has_display_name = True
                                continue

                            if op == NEW_INSTANCE_044:
                                out = ins.get_output() if hasattr(ins, 'get_output') else ''
                                if any(fc in out for fc in FILE_CLASSES_044):
                                    has_file_operation = True
                                continue

                            if op in INVOKE_OPS_044:
                                out = ins.get_output() if hasattr(ins, 'get_output') else ''
                                if 'getContentResolver' in out or 'ContentResolver' in out:
                                    has_content_resolver = True
                                if '->query(' in out:
                                    has_query = True
                                if any(fc in out and '-><init>' in out for fc in FILE_CLASSES_044):
                                    has_file_operation = True
                        except Exception:
                            continue

                    if has_content_resolver and has_query and has_display_name:
                        content_resolver_usage.append({
                            "class": class_name,
                            "method": method.name,
                            "has_file_operation": has_file_operation
                        })
                        if has_file_operation:
                            file_operations.append({
                                "class": class_name,
                                "method": method.name,
                                "severity": "HIGH"
                            })

            # Step 3: 分析結果
            if content_resolver_usage:
                results.append({
                    "issue": "ContentResolver.query() with _display_name detected",
                    "severity": "MEDIUM" if not file_operations else "HIGH",
                    "description": "Application queries _display_name from ContentResolver, which can be manipulated by attacker",
                    "affected_methods": content_resolver_usage
                })

            if file_operations:
                results.append({
                    "issue": "Potential Dirty Steam vulnerability - Unvalidated filename used in file operations",
                    "severity": "HIGH",
                    "description": "File operations detected in methods that query _display_name. If filename is not validated, attacker can use path traversal (../) to write files outside intended directory",
                    "recommendation": "Always sanitize filename: remove path separators (/,\\), remove '..' sequences, use File.getName() to extract basename only",
                    "affected_methods": file_operations
                })

            return jsonify({
                "has_finding": len(file_operations) > 0,
                "vulnerable_activities": vulnerable_activities,
                "results": results,
                "count": len(results)
            }), 200

        except Exception as e:
            return jsonify({
                "error": f"Analysis failed: {str(e)}"
            }), 500


    @app.route('/androguard/lab_054', methods=['GET'])
    def detect_lab_054():
        """
        對應 maldroid_main.py 中的 lab_054 - SQLite Encryption Extension (SEE)
        檢測 Lorg/sqlite/database/sqlite/SQLiteDatabase; 類別
        """
        results = []
        
        # check SQLite Encryption Extension (SEE)
        target_class = "Lorg/sqlite/database/sqlite/SQLiteDatabase;"
        
        if target_class in dx.classes:
            results.append({
                "class_found": True,
                "class_name": target_class,
                "description": "SQLite Encryption Extension (SEE) detected"
            })
        else:
            results.append({
                "class_found": False,
                "class_name": target_class,
                "description": "SQLite Encryption Extension (SEE) not found"
            })
        
        return jsonify({
            "results": results,
        }), 200

    @app.route('/androguard/lab_055', methods=['GET'])
    def detect_lab_055():
        """
        對應 maldroid_main.py 中的 lab_055 - SQLite PRAGMA key encryption
        檢測 PRAGMA key 相關的字串和方法
        """
        # 搜尋 PRAGMA key 相關的字串
        pragma_key_strings = []
        pragma_key_methods = []
        
        for _, method, method_analysis in iter_app_methods(dx):
            try:
                if not hasattr(method_analysis, 'get_instructions'):
                    continue
                instructions = list(method_analysis.get_instructions())

                for instruction in instructions:
                    # 1. const-string: check for PRAGMA key pattern
                    if instruction.get_op_value() in [0x1A, 0x1B]:
                        string_value = instruction.get_string()
                        if re.search(r'PRAGMA\s*key\s*=', string_value, re.IGNORECASE):
                            pragma_key_strings.append({
                                "class": method.class_name,
                                "method": method.name,
                                "string": string_value,
                                "description": "PRAGMA key string found"
                            })

                    # 2. execSQL call containing pragma
                    ins_output = instruction.get_output()
                    if 'execSQL' in ins_output and 'pragma' in ins_output.lower():
                        pragma_key_methods.append({
                            "class": method.class_name,
                            "method": method.name,
                            "instruction": ins_output,
                            "description": "PRAGMA key in execSQL call"
                        })

            except Exception:
                continue
        
        # 3. combine results
        total = len(pragma_key_strings) + len(pragma_key_methods)
        return jsonify({
            "results": pragma_key_strings + pragma_key_methods,
            "count": total,
            "has_finding": total > 0,
            "pragma_key_strings": pragma_key_strings,
            "pragma_key_methods": pragma_key_methods,
            "lab_id": "lab_055",
            "description": "SQLite PRAGMA key encryption detection"
        }), 200

    @app.route('/androguard/lab_056', methods=['GET'])
    def detect_lab_056():
        """
        Root Detection Implementation Check
        靜態分析偵測 APP 是否實作 Root Detection 機制，涵蓋 5 大類：
          1. SU binary path strings            (su 執行檔路徑字串)
          2. Root management package names     (root 管理 App 套件名稱)
          3. Build tags / system properties    (系統屬性 test-keys 等)
          4. Third-party root detection libs   (RootBeer / SafetyNet / Play Integrity)
          5. File.exists() checks              (判斷 su binary 是否存在)
        """

        ROOT_BINARY_PATHS = [
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
            "/system/sd/xbin/su", "/system/bin/failsafe/su",
            "/system/app/Superuser.apk", "/system/app/SuperSU",
            "/system/app/Superuser", "/data/data/com.noshufou.android.su",
            "/data/local.prop",
        ]

        ROOT_MANAGEMENT_PACKAGES = [
            "com.noshufou.android.su", "eu.chainfire.supersu",
            "com.koushikdutta.superuser", "com.thirdparty.superuser",
            "com.topjohnwu.magisk", "com.kingroot.kinguser",
            "com.kingo.root", "com.yellowes.su", "me.phh.superuser",
            # root cloaking apps
            "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
            "de.robv.android.xposed.installer", "com.saurik.substrate",
            "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
        ]

        BUILD_PROPERTY_INDICATORS = [
            "test-keys", "ro.debuggable", "ro.secure", "ro.build.selinux",
        ]

        # Third-party root detection library class prefixes
        ROOT_DETECTION_CLASSES = [
            ("Lcom/scottyab/rootbeer/RootBeer", "RootBeer Library"),
            ("Lcom/scottyab/rootbeer/RootBeerNative", "RootBeer Native Library"),
            ("Lcom/scottyab/rootchecker/", "RootChecker Library"),
        ]

        # Google SafetyNet / Play Integrity API class prefixes
        SAFETYNET_INTEGRITY_CLASSES = [
            ("Lcom/google/android/gms/safetynet/SafetyNet", "Google SafetyNet API"),
            ("Lcom/google/android/play/core/integrity/", "Google Play Integrity API"),
        ]

        su_binary_paths = []
        root_packages = []
        build_properties = []
        third_party_libs = []
        file_exists_checks = []

        # --- Scan all app methods for string patterns and API calls ---
        for class_name, method, method_analysis in iter_app_methods(dx):
            try:
                instructions = list(method_analysis.get_instructions())
            except Exception:
                continue

            for instruction in instructions:
                try:
                    op = instruction.get_op_value()
                    ins_out = instruction.get_output()
                    entry_base = {"class": class_name, "method": method.name}

                    # const-string / const-string-jumbo
                    if op in [0x1A, 0x1B]:
                        try:
                            string_val = instruction.get_string()
                        except Exception:
                            continue

                        # 1. SU binary path strings
                        if any(path in string_val for path in ROOT_BINARY_PATHS):
                            su_binary_paths.append({
                                **entry_base,
                                "string": string_val,
                                "category": "su_binary_path",
                                "description": "SU binary path string found"
                            })

                        # 2. Root management package name strings
                        if any(pkg in string_val for pkg in ROOT_MANAGEMENT_PACKAGES):
                            root_packages.append({
                                **entry_base,
                                "string": string_val,
                                "category": "root_package",
                                "description": "Root management app package name found"
                            })

                        # 3. Build tag / system property strings
                        if any(prop in string_val for prop in BUILD_PROPERTY_INDICATORS):
                            build_properties.append({
                                **entry_base,
                                "string": string_val,
                                "category": "build_property",
                                "description": "Build tag / system property check string found"
                            })

                    # invoke-* instructions
                    if 'invoke' in ins_out:
                        # 5. File.exists() checks
                        if 'exists' in ins_out and 'Ljava/io/File;' in ins_out:
                            file_exists_checks.append({
                                **entry_base,
                                "instruction": ins_out,
                                "category": "file_exists",
                                "description": "File.exists() call detected (potential su binary existence check)"
                            })

                except Exception:
                    continue

        # --- Check for third-party root detection library classes in dx ---
        for cls_prefix, lib_name in ROOT_DETECTION_CLASSES:
            for class_name in dx.classes:
                if class_name.startswith(cls_prefix):
                    third_party_libs.append({
                        "class": class_name,
                        "library": lib_name,
                        "category": "third_party_lib",
                        "description": "{} class detected".format(lib_name)
                    })
                    break  # one match per library is sufficient

        # --- Check for SafetyNet / Play Integrity API classes in dx ---
        for cls_prefix, api_name in SAFETYNET_INTEGRITY_CLASSES:
            for class_name in dx.classes:
                if class_name.startswith(cls_prefix):
                    third_party_libs.append({
                        "class": class_name,
                        "library": api_name,
                        "category": "root_detection_api",
                        "description": "{} class detected".format(api_name)
                    })
                    break

        all_findings = (
            su_binary_paths + root_packages + build_properties +
            third_party_libs + file_exists_checks
        )

        # has_finding = True means the app does NOT implement root detection (security issue)
        return jsonify({
            "has_finding": len(all_findings) == 0,
            "count": len(all_findings),
            "results": all_findings,
            "su_binary_paths": su_binary_paths,
            "root_packages": root_packages,
            "build_properties": build_properties,
            "third_party_libs": third_party_libs,
            "file_exists_checks": file_exists_checks,
            "lab_id": "lab_056",
            "description": "Root Detection implementation check"
        }), 200

    @app.route('/androguard/lab_069', methods=['GET'])
    def detect_lab_069():
        """
        Prevent Overlay Attack 
        """
        results = []

        try:
            # Get the parsed Android Manifest XML
            manifest_xml = a.get_android_manifest_xml()
            # Android Namespace (android_ns = android)
            android_ns = '{http://schemas.android.com/apk/res/android}'
            
            for element in manifest_xml.iter():
                filter_touches = element.get(f'{android_ns}filterTouchesWhenObscured')

                if filter_touches is not None:
                    element_name = element.get(f'{android_ns}name', element.tag)
                    results.append({
                        "element_tag": element.tag,
                        "element_name": element_name,
                        "filterTouchesWhenObscured": filter_touches,
                        "is_protected": filter_touches.lower() == "true"
                    })

        except Exception as e:
            return jsonify({
                "error": f"Failed to parse manifest: {str(e)}",
                "results": []
            }), 500
        
        return jsonify({
            "results": results,
            "count": len(results),
            "has_finding": any(r.get("is_protected", False) for r in results),
            "lab_id": "lab_069",
            "description": "Overlay Attack (Tapjacking) prevention detection"
        }), 200
    

    # Base on 4.1.2.1.2 行動應用程式應提供使用者拒絕蒐集敏感性資料之權利

    @app.route('/androguard/lab_070', methods=['GET'])
    def detect_lab_070():
        """
        4.1.2.1.2 行動應用程式應提供使用者拒絕蒐集敏感性資料之權利
        靜態驗證 App 是否實作 Android Runtime Permission 機制（含拒絕處理）

        Verdict logic:
          INFO    — 未宣告任何 dangerous permission，無需檢測
          FAIL    — 宣告了 dangerous permission 但完全沒有 runtime request 呼叫
          WARNING — 有 runtime request 但 onRequestPermissionsResult 未見 DENIED 分支
          PASS    — 有 runtime request 且有 DENIED 分支處理
        """

        ANDROID_DANGEROUS_PERMISSIONS = {
            "android.permission.CAMERA",
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_PHONE_NUMBERS",
            "android.permission.CALL_PHONE",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.RECEIVE_MMS",
            "android.permission.RECEIVE_WAP_PUSH",
            "android.permission.BODY_SENSORS",
            "android.permission.BODY_SENSORS_BACKGROUND",
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.GET_ACCOUNTS",
            "android.permission.USE_BIOMETRIC",
            "android.permission.USE_FINGERPRINT",
            "android.permission.BLUETOOTH_CONNECT",
            "android.permission.BLUETOOTH_SCAN",
            "android.permission.BLUETOOTH_ADVERTISE",
            "android.permission.NEARBY_WIFI_DEVICES",
            "android.permission.READ_MEDIA_IMAGES",
            "android.permission.READ_MEDIA_VIDEO",
            "android.permission.READ_MEDIA_AUDIO",
            "android.permission.READ_MEDIA_VISUAL_USER_SELECTED",
            "android.permission.UWB_RANGING",
            "android.permission.ACTIVITY_RECOGNITION",
            "android.permission.ANSWER_PHONE_CALLS",
            "android.permission.ACCEPT_HANDOVER",
            "android.permission.ADD_VOICEMAIL",
            "android.permission.USE_SIP",
        }

        # Step 1: 取得 Manifest 中宣告的 dangerous permissions
        try:
            all_permissions = list(a.get_permissions()) if a.get_permissions() else []
        except Exception:
            all_permissions = []

        declared_dangerous = [p for p in all_permissions if p in ANDROID_DANGEROUS_PERMISSIONS]

        if not declared_dangerous:
            return jsonify({
                "has_finding": False,
                "lab_id": "lab_070",
                "verdict": "INFO",
                "description": "No dangerous permissions declared — runtime permission check not applicable",
                "dangerous_permissions": [],
                "has_runtime_request": False,
                "has_denied_handling": False,
                "has_rationale_call": False,
                "runtime_request_found": [],
                "denied_handling_found": [],
                "rationale_call_found": [],
                "results": [],
                "count": 0
            }), 200

        # Step 2 & 4: 掃 DEX 找 runtime permission request 與 rationale 呼叫
        runtime_request_found = []
        rationale_call_found = []

        RUNTIME_REQUEST_PATTERNS = [
            "requestPermissions",
            "registerForActivityResult",
        ]

        for class_name, method, method_analysis in iter_app_methods(dx):
            try:
                if not hasattr(method_analysis, 'get_instructions'):
                    continue
                instructions = list(method_analysis.get_instructions())

                for instruction in instructions:
                    ins_output = instruction.get_output()

                    # Step 2: runtime permission request
                    for pattern in RUNTIME_REQUEST_PATTERNS:
                        if pattern in ins_output:
                            runtime_request_found.append({
                                "class": class_name,
                                "method": method.name,
                                "instruction": ins_output,
                                "pattern": pattern
                            })
                            break

                    # Step 4: shouldShowRequestPermissionRationale
                    if "shouldShowRequestPermissionRationale" in ins_output:
                        rationale_call_found.append({
                            "class": class_name,
                            "method": method.name,
                            "instruction": ins_output
                        })
            except Exception:
                continue

        # Step 3: 找 onRequestPermissionsResult 並確認有無 DENIED 分支
        # Branch opcodes: if-eq(0x32) if-ne(0x33) if-eqz(0x38) if-nez(0x39)
        #                 if-ltz(0x3a) if-gez(0x3b) if-gtz(0x3c) if-lez(0x3d)
        BRANCH_OPCODES = {0x32, 0x33, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d}
        denied_handling_found = []

        for class_name, method, method_analysis in iter_app_methods(dx):
            try:
                if method.name != "onRequestPermissionsResult":
                    continue
                if not hasattr(method_analysis, 'get_instructions'):
                    continue
                instructions = list(method_analysis.get_instructions())

                has_branch = False
                for instruction in instructions:
                    if instruction.get_op_value() in BRANCH_OPCODES:
                        has_branch = True
                        break

                denied_handling_found.append({
                    "class": class_name,
                    "method": method.name,
                    "has_branch": has_branch,
                    "description": "DENIED handling branch detected" if has_branch
                                   else "onRequestPermissionsResult found but no branch instruction detected"
                })
            except Exception:
                continue

        # Step 5: 組合 verdict
        has_runtime_request = len(runtime_request_found) > 0
        has_denied_handling = any(r.get("has_branch") for r in denied_handling_found)
        has_rationale_call = len(rationale_call_found) > 0

        if not has_runtime_request:
            verdict = "FAIL"
        elif not has_denied_handling:
            verdict = "WARNING"
        else:
            verdict = "PASS"

        all_results = runtime_request_found + denied_handling_found + rationale_call_found

        return jsonify({
            "has_finding": verdict in ["FAIL", "WARNING"],
            "lab_id": "lab_070",
            "verdict": verdict,
            "description": "Runtime permission refusal right detection (MAS V4.0 4.1.2.1.2)",
            "dangerous_permissions": declared_dangerous,
            "has_runtime_request": has_runtime_request,
            "has_denied_handling": has_denied_handling,
            "has_rationale_call": has_rationale_call,
            "runtime_request_found": runtime_request_found,
            "denied_handling_found": denied_handling_found,
            "rationale_call_found": rationale_call_found,
            "results": all_results,
            "count": len(all_results)
        }), 200

    # 4.1.2.3.16行動應用程式應避免將敏感性資料儲存或輸出於系統日誌
    @app.route('/androguard/lab_071', methods=['GET'])
    def detect_lab_071():
        """
        Detect debug/verbose log calls (Log.d / Log.v) in app-owned code.
        These should never exist in a release build.
        Third-party libraries are excluded via iter_app_methods.
        """

        # Only HIGH severity: Log.d and Log.v
        HIGH_LOG_METHODS = {"d", "v"}
        TARGET_CLASS = "Landroid/util/Log;"

        findings = []

        for class_name, method_analysis, method in iter_app_methods(dx):
            try:
                instructions = list(method.get_instructions())
            except Exception:
                continue

            for instruction in instructions:
                try:
                    op = instruction.get_op_value()
                    if op not in [0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78]:
                        continue

                    ins_out = instruction.get_output()
                    if TARGET_CLASS not in ins_out:
                        continue

                    for log_method in HIGH_LOG_METHODS:
                        if "->{} ".format(log_method) in ins_out or \
                           "->{}(".format(log_method) in ins_out:
                            findings.append({
                                "class":       class_name,
                                "method":      method.get_name(),
                                "log_api":     "Log.{}()".format(log_method),
                                "instruction": ins_out,
                                "description": "Debug log call found: Log.{}() should be removed in release build".format(log_method)
                            })
                            break
                except Exception:
                    continue

        return jsonify({
            "has_finding": len(findings) > 0,
            "count":       len(findings),
            "results":     findings,
            "lab_id":      "lab_071",
            "description": "Debug log detection: Log.d() / Log.v() calls found in app code (should not exist in release build)"
        }), 200

    #4.1.2.3.11 檢查行動應用程式於使用者輸入敏感性資料時，是否未自動修正且未帶入可能字串
    @app.route('/androguard/lab_072', methods=['GET'])
    def detect_lab_072():
        """
        Keyboard Cache Protection Check (4.1.2.3.11)
        掃描 res/layout/ 下所有 layout XML，找出 EditText 敏感欄位未設定
        keyboard cache protection (inputType) 的情況。

        Severity by field sensitivity:
          CRITICAL - 明確敏感欄位 (password / pin / cvv / ssn) 未受保護
          WARNING  - 可能敏感欄位 (otp / token / secret / account) 未受保護
        """
        try:
            from androguard.core.axml import AXMLPrinter  # androguard 4.x
        except ImportError:
            from androguard.core.bytecodes.axml import AXMLPrinter  # androguard 3.x
        import xml.etree.ElementTree as ET

        ANDROID_NS = '{http://schemas.android.com/apk/res/android}'

        # Android inputType bitmask constants
        TYPE_MASK_CLASS           = 0x0000000f
        TYPE_MASK_VARIATION       = 0x00000ff0
        TYPE_CLASS_TEXT           = 0x01
        TYPE_CLASS_NUMBER         = 0x02
        TEXT_PASSWORD_VARIATIONS  = {0x80, 0x90, 0xe0}  # password, visiblePwd, webPwd
        NUMBER_PASSWORD_VARIATION = 0x10                 # numberPassword (PIN)
        FLAG_NO_SUGGESTIONS       = 0x00080000

        def is_safe_input_type(raw_val):
            try:
                v = int(raw_val, 0) if isinstance(raw_val, str) else int(raw_val)
            except (ValueError, TypeError):
                return False
            input_class     = v & TYPE_MASK_CLASS
            input_variation = v & TYPE_MASK_VARIATION
            if input_class == TYPE_CLASS_TEXT and input_variation in TEXT_PASSWORD_VARIATIONS:
                return True
            if input_class == TYPE_CLASS_NUMBER and input_variation == NUMBER_PASSWORD_VARIATION:
                return True
            if v & FLAG_NO_SUGGESTIONS:
                return True
            return False

        def is_edittext_tag(tag):
            localname   = tag.split('}')[-1] if '}' in tag else tag
            simple_name = localname.split('.')[-1]
            return simple_name.endswith('EditText') or simple_name == 'TextInputEditText'

        # CRITICAL: 明確敏感欄位
        CRITICAL_RE = re.compile(
            r'(password|passwd|pwd|pin\b|cvv|cvc|ssn|credit.?card|card.?num)',
            re.IGNORECASE
        )
        # WARNING: 可能敏感欄位
        WARNING_RE = re.compile(
            r'(otp|token|secret|auth.?code|account.?num)',
            re.IGNORECASE
        )

        findings     = []
        all_files    = a.get_files()
        layout_files = [f for f in all_files if f.startswith('res/layout/') and f.endswith('.xml')]

        for layout_file in layout_files:
            try:
                raw = a.get_file(layout_file)
                if not raw:
                    continue
                xml_str = AXMLPrinter(raw).get_buff()
                root    = ET.fromstring(xml_str)
            except Exception:
                continue

            for elem in root.iter():
                if not is_edittext_tag(elem.tag):
                    continue

                hint       = elem.get(f'{ANDROID_NS}hint', '')
                elem_id    = elem.get(f'{ANDROID_NS}id', '')
                input_type = elem.get(f'{ANDROID_NS}inputType')
                combined   = hint + ' ' + elem_id

                if CRITICAL_RE.search(combined):
                    severity = "CRITICAL"
                elif WARNING_RE.search(combined):
                    severity = "WARNING"
                else:
                    continue

                if input_type is None:
                    detail = "No inputType attribute — defaults to plain text (full autocorrect/autocomplete)"
                elif is_safe_input_type(input_type):
                    continue  # protected, skip
                else:
                    detail = "inputType={} does not include password/noSuggestions protection".format(input_type)

                findings.append({
                    "file":        layout_file,
                    "tag":         elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag,
                    "hint":        hint,
                    "id":          elem_id,
                    "input_type":  input_type,
                    "severity":    severity,
                    "description": detail
                })

        return jsonify({
            "has_finding":     len(findings) > 0,
            "count":           len(findings),
            "results":         findings,
            "critical":        [f for f in findings if f["severity"] == "CRITICAL"],
            "warning":         [f for f in findings if f["severity"] == "WARNING"],
            "scanned_layouts": len(layout_files),
            "lab_id":          "lab_072",
            "description":     "Keyboard cache protection: sensitive EditText fields without inputType password/noSuggestions"
        }), 200



    # 4.1.2.3.14 — 備份資料不應存有敏感性資料
    @app.route('/androguard/lab_073', methods=['GET'])
    def detect_lab_073():
        """
        Backup Sensitive Data Protection Check (4.1.2.3.14)

        Check 1 — AndroidManifest.xml attributes:
          - android:allowBackup  (missing or "true" = risk)
          - android:fullBackupContent (API 23-30 exclusion rules file)
          - android:dataExtractionRules (API 31+ exclusion rules file)

        Check 2 — Smali sensitive storage API scan:
          Detect calls to SharedPreferences / SQLite / File / External Storage APIs
          in app-owned code, indicating data that would be included in a backup.
        """

        ANDROID_NS = '{http://schemas.android.com/apk/res/android}'

        SENSITIVE_BACKUP_APIS = {
            # SharedPreferences
            "getSharedPreferences":        "Landroid/content/Context;",
            "getDefaultSharedPreferences": "Landroid/preference/PreferenceManager;",
            # SQLite
            "openOrCreateDatabase":        "Landroid/content/Context;",
            "getWritableDatabase":         "Landroid/database/sqlite/SQLiteOpenHelper;",
            "getReadableDatabase":         "Landroid/database/sqlite/SQLiteOpenHelper;",
            # Internal File Storage
            "openFileOutput":              "Landroid/content/Context;",
            "getFilesDir":                 "Landroid/content/Context;",
            "getCacheDir":                 "Landroid/content/Context;",
            # External Storage
            "getExternalStorageDirectory": "Landroid/os/Environment;",
            "getExternalFilesDir":         "Landroid/content/Context;",
            "getExternalCacheDir":         "Landroid/content/Context;",
        }

        # ----------------------------------------------------------------
        # Check 1: AndroidManifest.xml
        # ----------------------------------------------------------------
        manifest_result = {
            "allow_backup":          None,
            "full_backup_content":   None,
            "data_extraction_rules": None,
            "allow_backup_risk":     False,
            "has_backup_exclusion":  False,
        }

        try:
            manifest_xml = a.get_android_manifest_xml()
            app_element = manifest_xml.find('application')
            if app_element is not None:
                allow_backup = app_element.get(ANDROID_NS + 'allowBackup')
                full_backup  = app_element.get(ANDROID_NS + 'fullBackupContent')
                data_extract = app_element.get(ANDROID_NS + 'dataExtractionRules')

                manifest_result['allow_backup']          = allow_backup
                manifest_result['full_backup_content']   = full_backup
                manifest_result['data_extraction_rules'] = data_extract

                # allowBackup missing (defaults True pre-API31) or explicitly True
                if allow_backup is None or allow_backup.lower() == 'true':
                    manifest_result['allow_backup_risk'] = True

                # Has at least one exclusion rule file configured
                if full_backup or data_extract:
                    manifest_result['has_backup_exclusion'] = True
        except Exception as e:
            manifest_result['error'] = str(e)

        # ----------------------------------------------------------------
        # Check 2: Smali sensitive storage API scan
        # ----------------------------------------------------------------
        storage_api_calls = []

        for class_name, method_analysis, method in iter_app_methods(dx):
            try:
                instructions = list(method.get_instructions())
            except Exception:
                continue

            for instruction in instructions:
                try:
                    op = instruction.get_op_value()
                    if op not in [0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78]:
                        continue

                    ins_out = instruction.get_output()

                    for method_name, target_class in SENSITIVE_BACKUP_APIS.items():
                        # Match on method name only — smali may reference a subclass
                        # (e.g. Landroid/app/Activity; instead of Landroid/content/Context;)
                        # so strict class check would miss inherited calls.
                        if "->{}(".format(method_name) not in ins_out:
                            continue
                        storage_api_calls.append({
                            "class":  class_name,
                            "method": method.get_name(),
                            "api":    method_name,
                        })
                        break
                except Exception:
                    continue

        # ----------------------------------------------------------------
        # Verdict
        # ----------------------------------------------------------------
        # Finding if allowBackup is risky AND sensitive storage APIs are used
        # OR if allowBackup is risky with no exclusion rules configured
        has_finding = (
            manifest_result['allow_backup_risk'] and
            len(storage_api_calls) > 0 and
            not manifest_result['has_backup_exclusion']
        )

        return jsonify({
            "has_finding":       has_finding,
            "manifest":          manifest_result,
            "storage_api_calls": storage_api_calls,
            "storage_api_count": len(storage_api_calls),
            "lab_id":            "lab_073",
            "description":       "Backup sensitive data protection check (allowBackup + sensitive storage API scan)"
        }), 200

    # 4.1.2.3.8 — 敏感性資料應避免出現於程式碼
    @app.route('/androguard/lab_074', methods=['GET'])
    def detect_lab_074():
        """
        4.1.2.3.8 - Sensitive data hardcoded in source code detection.
        Two sources:
          A) Smali bytecode  - const-string instructions in app-owned methods
          B) res/values XML  - <string name="..."> resource entries

        Matching logic:
          keyword match  -> flag immediately (no entropy gate)
          pattern match  -> only flag if Shannon entropy >= ENTROPY_THRESHOLD
        """
        import math
        import re as _re
        import xml.etree.ElementTree as ET

        SENSITIVE_KEYWORDS = [
            "api_key", "apikey", "secret", "password", "passwd",
            "token", "auth", "credential", "private_key", "access_key",
            "client_secret", "encryption_key", "signing_key",
            "bearer", "oauth", "x_api_key", "authorization",
            "db_password", "database_url", "aws_secret", "stripe_key",
        ]

        SECRET_PATTERNS = {
            "Google API Key": _re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
            "AWS Access Key":  _re.compile(r"AKIA[0-9A-Z]{16}"),
            "JWT Token":       _re.compile(r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+"),
        }

        ENTROPY_THRESHOLD = 4.5

        def shannon_entropy(s):
            if not s:
                return 0.0
            freq = {}
            for c in s:
                freq[c] = freq.get(c, 0) + 1
            length = float(len(s))
            return -sum((v / length) * math.log(v / length, 2) for v in freq.values())

        def keyword_hit(text):
            lower = text.lower()
            return any(kw in lower for kw in SENSITIVE_KEYWORDS)

        def pattern_hit(value):
            for name, pat in SECRET_PATTERNS.items():
                if pat.search(value):
                    return name
            return None

        smali_findings = []
        xml_findings   = []

        # --- Source A: smali bytecode ---
        for class_name, method_analysis, method in iter_app_methods(dx):
            try:
                instructions = list(method.get_instructions())
            except Exception:
                continue

            method_name = method.get_name()

            for instruction in instructions:
                try:
                    if instruction.get_op_value() not in [0x1A, 0x1B]:
                        continue
                    string_val = instruction.get_string()
                    if not string_val or len(string_val) < 6:
                        continue

                    match_reason = None

                    if keyword_hit(string_val):
                        match_reason = "keyword_match"
                    else:
                        pat_name = pattern_hit(string_val)
                        if pat_name and shannon_entropy(string_val) >= ENTROPY_THRESHOLD:
                            match_reason = "pattern:{}".format(pat_name)

                    if match_reason:
                        smali_findings.append({
                            "source":       "smali",
                            "class":        class_name,
                            "method":       method_name,
                            "string":       string_val,
                            "match_reason": match_reason,
                            "entropy":      round(shannon_entropy(string_val), 3),
                            "description":  "Hardcoded sensitive string found in bytecode"
                        })
                except Exception:
                    continue

        # --- Source B: res/values XML ---
        try:
            for file_path in a.get_files():
                if "res/values" not in file_path or not file_path.endswith(".xml"):
                    continue
                try:
                    raw = a.get_file(file_path)
                    root = ET.fromstring(raw)
                    for elem in root.iter("string"):
                        name_attr = elem.get("name", "")
                        value     = (elem.text or "").strip()
                        if not name_attr or not value:
                            continue

                        match_reason = None

                        if keyword_hit(name_attr):
                            match_reason = "keyword_match:name"
                        elif keyword_hit(value):
                            match_reason = "keyword_match:value"
                        else:
                            pat_name = pattern_hit(value)
                            if pat_name and shannon_entropy(value) >= ENTROPY_THRESHOLD:
                                match_reason = "pattern:{}".format(pat_name)

                        if match_reason:
                            xml_findings.append({
                                "source":        "xml",
                                "file":          file_path,
                                "resource_name": name_attr,
                                "value":         value,
                                "match_reason":  match_reason,
                                "entropy":       round(shannon_entropy(value), 3),
                                "description":   "Sensitive string resource found in XML"
                            })
                except Exception:
                    continue
        except Exception:
            pass
        
        all_findings = smali_findings + xml_findings

        return jsonify({
            "has_finding":     len(all_findings) > 0,
            "count":           len(all_findings),
            "results":         all_findings,
            "smali_findings":  smali_findings,
            "xml_findings":    xml_findings,
            "lab_id":          "lab_074",
            "description":     "Hardcoded sensitive data detection (bytecode + XML resources)"
        }), 200

    #4.1.2.3.10 — 敏感性資料應儲存於系統憑證儲存設施
    @app.route('/androguard/lab_075', methods=['GET'])
    def detect_lab_075():
        """
        MAS 4.1.2.3.10 / MASVS-STORAGE-1 / MASTG-TEST-0051 / CWE-312,321
        Detect KeyStore.getInstance() calls in app-owned smali code and classify
        the provider argument as secure (AndroidKeyStore) or insecure.
        """
        SECURE_PROVIDER = "AndroidKeyStore"
        TARGET_CLASS    = "Ljava/security/KeyStore;"
        TARGET_METHOD   = "->getInstance("
        INVOKE_OPS      = {0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78}

        secure_list   = []
        insecure_list = []

        for class_name, method_analysis, method in iter_app_methods(dx):
            try:
                instructions = list(method.get_instructions())
            except Exception:
                continue

            method_name = method.get_name()

            for idx, ins in enumerate(instructions):
                try:
                    if ins.get_op_value() not in INVOKE_OPS:
                        continue

                    ins_out = ins.get_output()
                    if TARGET_CLASS not in ins_out or TARGET_METHOD not in ins_out:
                        continue

                    # Scan up to 5 previous instructions for the const-string provider arg
                    provider = None
                    for back in range(1, min(6, idx + 1)):
                        prev = instructions[idx - back]
                        if prev.get_op_value() in [0x1A, 0x1B]:
                            provider = prev.get_string()
                            break

                    entry = {
                        "class":    class_name,
                        "method":   method_name,
                        "provider": provider if provider else "unknown",
                    }

                    if provider == SECURE_PROVIDER:
                        secure_list.append(entry)
                    else:
                        insecure_list.append(entry)

                except Exception:
                    continue

        no_keystore = (len(secure_list) == 0 and len(insecure_list) == 0)

        if no_keystore:
            verdict     = "WARNING"
            has_finding = True
        elif len(insecure_list) == 0:
            verdict     = "PASS"
            has_finding = False
        elif len(secure_list) > 0:
            verdict     = "WARNING"
            has_finding = True
        else:
            verdict     = "CRITICAL"
            has_finding = True

        return jsonify({
            "verdict":      verdict,
            "has_finding":  has_finding,
            "secure_list":  secure_list,
            "insecure_list": insecure_list,
            "no_keystore":  no_keystore,
            "count":        len(insecure_list),
            "lab_id":       "lab_075",
        }), 200

    #4.1.2.3.5 — 行動應用程式應避免將敏感性資料儲存於冗餘檔案或日誌檔案中 (replaces legacy lab_063)
    @app.route('/androguard/lab_063', methods=['GET'])
    def detect_lab_063():
        """
        MAS 4.1.2.3.5 / MASVS-STORAGE-2 / OWASP Mobile 2024 M9

        Detects File.delete() calls co-located with a sensitive keyword
        string (password/token/secret, etc.) in the same method.

        Severity:
          NOTICE - delete() co-located with a sensitive keyword string in
                   the same method (plausible unsafe cleanup of sensitive
                   data)
          (a bare delete() with no co-located sensitive keyword is silently
           ignored)
        """
        SENSITIVE_KEYWORDS = [
            "password", "passwd", "secret", "api_key", "apikey",
            "token", "credential", "auth_token", "access_key",
            "private_key", "client_secret", "bearer", "authorization",
        ]

        DELETE_SINK = "Ljava/io/File;->delete("
        INVOKE_OPS  = {0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78}

        def keyword_hit(text):
            lower = text.lower()
            for kw in SENSITIVE_KEYWORDS:
                if kw in lower:
                    return kw
            return None

        findings = []

        for class_name, method_analysis, method in iter_app_methods(dx):
            try:
                instructions = list(method.get_instructions())
            except Exception:
                continue

            method_name = method.get_name()

            has_delete     = False
            local_keywords = []

            for ins in instructions:
                try:
                    op = ins.get_op_value()

                    if op in [0x1A, 0x1B]:
                        s = ins.get_string()
                        if s and len(s) >= 4:
                            kw = keyword_hit(s)
                            if kw:
                                local_keywords.append(kw)
                        continue

                    if op in INVOKE_OPS:
                        out = ins.get_output() if hasattr(ins, 'get_output') else ''
                        if DELETE_SINK in out:
                            has_delete = True
                except Exception:
                    continue

            if has_delete and local_keywords:
                findings.append({
                    "class":    class_name,
                    "method":   method_name,
                    "severity": "NOTICE",
                })

        return jsonify({
            "has_finding": len(findings) > 0,
            "count":       len(findings),
            "results":     findings,
            "lab_id":      "lab_063",
            "description": "Unsafe deletion of files that plausibly hold sensitive data (same-method keyword correlation)"
        }), 200

    #4.1.2.3.12
    @app.route('/androguard/lab_076', methods=['GET'])
    def detect_lab_076():
        """
        LAB_076: Deep Link Security (manifest-only check).
        Enumerate <activity> with action.VIEW + category.BROWSABLE + <data scheme=...>
        and flag three risks:
          HIGH   - scheme="http"                                  (MITM)
          MEDIUM - http/https without android:autoVerify="true"   (host hijack)
          MEDIUM - non-http(s) scheme without host attribute      (scheme hijack)
        """
        NS  = '{http://schemas.android.com/apk/res/android}'
        VIEW      = 'android.intent.action.VIEW'
        BROWSABLE = 'android.intent.category.BROWSABLE'

        entries = []  # one record per deep link <intent-filter>; risks list inside
        try:
            manifest_xml = a.get_android_manifest_xml()

            for act in manifest_xml.findall('.//activity'):
                name = act.get(NS + 'name', '')
                if not name:
                    continue

                for f in act.findall('intent-filter'):
                    if not any(x.get(NS + 'name') == VIEW      for x in f.findall('action')):
                        continue
                    if not any(x.get(NS + 'name') == BROWSABLE for x in f.findall('category')):
                        continue

                    auto_verify = f.get(NS + 'autoVerify', '').lower() == 'true'

                    for d in f.findall('data'):
                        scheme = d.get(NS + 'scheme', '')
                        if not scheme:
                            continue
                        host = d.get(NS + 'host', '')
                        sl   = scheme.lower()

                        risks = []
                        if sl == 'http':
                            risks.append(('HIGH',   'http scheme — MITM risk; use https'))
                        if sl in ('http', 'https') and not auto_verify:
                            risks.append(('MEDIUM', 'http(s) without android:autoVerify="true" — host hijack risk'))
                        if sl not in ('http', 'https') and not host:
                            risks.append(('MEDIUM', 'custom scheme without host — scheme hijack risk'))

                        entries.append({
                            'activity':    name,
                            'scheme':      scheme,
                            'host':        host,
                            'auto_verify': auto_verify,
                            'risks':       risks,
                        })

            findings = [e for e in entries if e['risks']]
            return jsonify({
                'has_finding': len(findings) > 0,
                'lab_id':      'lab_076',
                'description': 'Deep link manifest check (scheme / autoVerify / host)',
                'entries':     entries,
                'results':     findings,
                'count':       len(findings),
            }), 200

        except Exception as e:
            return jsonify({
                'error':       'lab_076 failed: {}'.format(e),
                'has_finding': False,
                'lab_id':      'lab_076',
                'count':       0,
            }), 500

    @app.route('/androguard/lab_077', methods=['GET'])
    def detect_lab_077():
        """
        LAB_077: Deep Link Injection (same-method source->sink heuristic).
        For each Activity class that declares a deep link intent-filter
        (action.VIEW + category.BROWSABLE + <data scheme=...>), scan its methods
        and flag any method that calls BOTH:
          Source: Intent.getData / Uri.getQueryParameter / getPath / getFragment / etc.
          Sink:   WebView.loadUrl / Intent.parseUri / new File / execSQL / rawQuery / Runtime.exec
        Heuristic only — no taint tracking. Manual review required.
        """
        NS        = '{http://schemas.android.com/apk/res/android}'
        VIEW      = 'android.intent.action.VIEW'
        BROWSABLE = 'android.intent.category.BROWSABLE'

        SOURCES = [
            'Landroid/content/Intent;->getData',
            'Landroid/net/Uri;->getQueryParameter',
            'Landroid/net/Uri;->getQueryParameterNames',
            'Landroid/net/Uri;->getPath',
            'Landroid/net/Uri;->getPathSegments',
            'Landroid/net/Uri;->getLastPathSegment',
            'Landroid/net/Uri;->getFragment',
            'Landroid/net/Uri;->getEncodedQuery',
        ]

        # (smali_signature_substring, friendly_name, risk_label)
        SINKS = [
            ('Landroid/webkit/WebView;->loadUrl',                  'WebView.loadUrl()',             'Open Redirect / XSS'),
            ('Landroid/webkit/WebView;->loadDataWithBaseURL',      'WebView.loadDataWithBaseURL()', 'Open Redirect / XSS'),
            ('Landroid/content/Intent;->parseUri',                 'Intent.parseUri()',             'Intent Redirection'),
            ('Ljava/io/File;-><init>',                             'new File()',                    'Path Traversal'),
            ('Ljava/io/FileInputStream;-><init>',                  'new FileInputStream()',         'Path Traversal'),
            ('Ljava/io/FileOutputStream;-><init>',                 'new FileOutputStream()',        'Path Traversal'),
            ('Landroid/database/sqlite/SQLiteDatabase;->execSQL',  'SQLiteDatabase.execSQL()',      'SQL Injection'),
            ('Landroid/database/sqlite/SQLiteDatabase;->rawQuery', 'SQLiteDatabase.rawQuery()',     'SQL Injection'),
            ('Ljava/lang/Runtime;->exec',                          'Runtime.exec()',                'Command Injection'),
        ]

        INVOKE_OPS = {0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78}

        findings = []
        try:
            # Step 1: collect deep link activity classes from manifest
            manifest_xml      = a.get_android_manifest_xml()
            package_name      = a.get_package() or ''
            deep_link_classes = set()

            for act in manifest_xml.findall('.//activity'):
                name = act.get(NS + 'name', '')
                if not name:
                    continue
                for f in act.findall('intent-filter'):
                    if not any(x.get(NS + 'name') == VIEW      for x in f.findall('action')):
                        continue
                    if not any(x.get(NS + 'name') == BROWSABLE for x in f.findall('category')):
                        continue
                    if not any(d.get(NS + 'scheme') for d in f.findall('data')):
                        continue
                    full_class = resolve_activity_name(package_name, name)
                    deep_link_classes.add('L' + full_class.replace('.', '/') + ';')
                    break

            if not deep_link_classes:
                return jsonify({
                    'has_finding': False,
                    'message':     'No deep link activity found',
                    'lab_id':      'lab_077',
                    'description': 'Deep link injection (source->sink heuristic)',
                    'count':       0,
                    'results':     [],
                }), 200

            # Step 2: scan methods in deep link classes
            for class_name, method, method_analysis in iter_app_methods(dx):
                if class_name not in deep_link_classes:
                    continue

                try:
                    instructions = list(method_analysis.get_instructions())
                except Exception:
                    continue

                sources_hit = []
                sinks_hit   = []

                for ins in instructions:
                    try:
                        if ins.get_op_value() not in INVOKE_OPS:
                            continue
                        out = ins.get_output()

                        for src in SOURCES:
                            if src in out:
                                short = src.split('->')[-1] + '()'
                                if short not in sources_hit:
                                    sources_hit.append(short)
                                break

                        for sink_sig, sink_name, risk in SINKS:
                            if sink_sig in out:
                                if (sink_name, risk) not in sinks_hit:
                                    sinks_hit.append((sink_name, risk))
                                break
                    except Exception:
                        continue

                if sources_hit and sinks_hit:
                    for sink_name, risk in sinks_hit:
                        findings.append({
                            'class':    class_name,
                            'method':   method.name,
                            'severity': 'HIGH',
                            'sources':  sources_hit,
                            'sink':     sink_name,
                            'risk':     risk,
                        })

            return jsonify({
                'has_finding': len(findings) > 0,
                'lab_id':      'lab_077',
                'description': 'Deep link injection (source->sink in same method, heuristic)',
                'count':       len(findings),
                'results':     findings,
            }), 200

        except Exception as e:
            return jsonify({
                'error':       'lab_077 failed: {}'.format(e),
                'has_finding': False,
                'lab_id':      'lab_077',
                'count':       0,
            }), 500

    # 4.1.5.1.2 — ZIP Path Traversal (ZipSlip) detection
    @app.route('/androguard/lab_078', methods=['GET'])
    def detect_lab_078():
        """
        Detect ZipSlip (CVE-2020-8913 pattern): app extracts ZIP entries via
        ZipInputStream / ZipFile.entries() and constructs File without verifying
        that the resolved path stays within the target directory.

        Per-method feature flags:
          has_zip_iter         - getNextEntry() / ZipFile.entries()
          has_get_name         - ZipEntry.getName()
          has_file_new         - new File(...) construction
          has_canonical_check  - getCanonicalPath() called anywhere in method
          has_dotdot_check     - const-string ".." appears in method
        Flag if (has_zip_iter & has_get_name & has_file_new) and
                NOT (has_canonical_check or has_dotdot_check).
        """
        ZIP_ITER_TOKENS = [
            "Ljava/util/zip/ZipInputStream;->getNextEntry(",
            "Ljava/util/zip/ZipFile;->entries(",
        ]
        GET_NAME_TOKEN = "Ljava/util/zip/ZipEntry;->getName("
        FILE_CLASS     = "Ljava/io/File;"
        CANONICAL_TOKEN = "->getCanonicalPath("
        INVOKE_OPS = {0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78}
        NEW_INSTANCE_OP = 0x22

        findings = []

        for class_name, method_analysis, method in iter_app_methods(dx):
            try:
                instructions = list(method.get_instructions())
            except Exception:
                continue

            method_name = method.get_name()

            has_zip_iter        = False
            has_get_name        = False
            has_file_new        = False
            has_canonical_check = False
            has_dotdot_check    = False

            for ins in instructions:
                try:
                    op = ins.get_op_value()

                    if op == NEW_INSTANCE_OP:
                        out = ins.get_output() if hasattr(ins, 'get_output') else ''
                        if FILE_CLASS in out:
                            has_file_new = True
                        continue

                    if op in [0x1A, 0x1B]:
                        s = ins.get_string()
                        if s and ".." in s:
                            has_dotdot_check = True
                        continue

                    if op in INVOKE_OPS:
                        out = ins.get_output() if hasattr(ins, 'get_output') else ''
                        if not has_zip_iter:
                            for t in ZIP_ITER_TOKENS:
                                if t in out:
                                    has_zip_iter = True
                                    break
                        if not has_get_name and GET_NAME_TOKEN in out:
                            has_get_name = True
                        if not has_canonical_check and CANONICAL_TOKEN in out:
                            has_canonical_check = True

                except Exception:
                    continue

            if has_zip_iter and has_get_name and has_file_new and \
               not (has_canonical_check or has_dotdot_check):
                missing = []
                if not has_canonical_check:
                    missing.append("getCanonicalPath")
                if not has_dotdot_check:
                    missing.append("dotdot_string_check")
                findings.append({
                    "class":          class_name,
                    "method":         method_name,
                    "missing_check":  ",".join(missing),
                    "description":    "ZIP entry extracted to File without path validation",
                })

        verdict = "CRITICAL" if findings else "PASS"

        return jsonify({
            "verdict":     verdict,
            "has_finding": len(findings) > 0,
            "findings":    findings,
            "count":       len(findings),
            "lab_id":      "lab_078",
        }), 200

    # 4.1.2.4.1 — Cleartext HTTP Traffic Detection (replaces legacy lab_001)
    @app.route('/androguard/lab_001', methods=['GET'])
    def detect_lab_001():
        """
        Three-layer SSL / cleartext traffic detection:
          Layer 1: AndroidManifest.application[@usesCleartextTraffic]
          Layer 2: res/xml network_security_config (base-config / domain-config)
          Layer 3: Smali source->sink: const-string "http://..." + network sink
                   (URL/openConnection, HttpURLConnection, WebView.loadUrl,
                    OkHttpClient.newCall, Volley StringRequest)

        Severity:
          CRITICAL - http URL flows to a network sink in same method
          WARNING  - http URLs found but no co-located sink (possibly dead code,
                     namespaces filtered out earlier)
          INFO     - manifest says usesCleartextTraffic=false but http URLs still
                     present in code (blocked by OS but should be removed)
        """
        import xml.etree.ElementTree as ET
        try:
            from androguard.core.axml import AXMLPrinter  # androguard 4.x
        except ImportError:
            from androguard.core.bytecodes.axml import AXMLPrinter  # androguard 3.x

        ANDROID_NS = '{http://schemas.android.com/apk/res/android}'

        # ---- Namespace / framework URI exclusion (extends legacy whitelist) ----
        NAMESPACE_PREFIXES = (
            "http://schemas.android.com/", "http://www.w3.org/",
            "http://apache.org/", "http://xml.org/", "http://java.sun.com/",
            "http://localhost", "http://127.0.0.1",
            "http://ns.adobe.com/", "http://www.inkscape.org/",
            "http://www.sketchapp.com/", "http://www.bohemiancoding.com/",
            "http://relaxng.org/", "http://exslt.org/", "http://xmlpull.org/",
            "http://json-schema.org/", "http://iptc.org/",
        )
        NAMESPACE_SUFFIXES = (
            "/namespace", "-dtd", ".dtd", "-handler", "-instance",
        )
        EXAMPLE_HOSTS = (
            "http://example.com", "http://www.example.com",
            "http://hostname/",
        )

        def is_namespace_or_example(url):
            if not url:
                return True
            for p in NAMESPACE_PREFIXES:
                if url.startswith(p):
                    return True
            for s in NAMESPACE_SUFFIXES:
                if url.endswith(s):
                    return True
            for e in EXAMPLE_HOSTS:
                if url == e or url == e + "/":
                    return True
            return False

        # ---- Layer 1: AndroidManifest ----
        manifest_cleartext_allowed = True   # API < 28 default true, API >= 28 default false
        manifest_attr_value        = None
        nsc_resource_name          = None

        try:
            mx = a.get_android_manifest_xml()
            app_elem = mx.find('.//application')
            if app_elem is not None:
                v = app_elem.get(ANDROID_NS + 'usesCleartextTraffic')
                if v is not None:
                    manifest_attr_value = v
                    manifest_cleartext_allowed = (str(v).lower() == 'true')
                nsc_resource_name = app_elem.get(ANDROID_NS + 'networkSecurityConfig')
        except Exception:
            pass

        target_sdk = 0
        try:
            target_sdk = int(a.get_target_sdk_version() or 0)
        except Exception:
            pass
        if manifest_attr_value is None and target_sdk >= 28:
            manifest_cleartext_allowed = False

        # ---- Layer 2: Network Security Config ----
        nsc_summary = {
            "present":              False,
            "base_cleartext":       None,   # True / False / None
            "domain_configs":       [],     # [{cleartext, domains}]
        }

        if nsc_resource_name:
            nsc_filename_hint = nsc_resource_name.split('/')[-1]
            for fp in a.get_files():
                if not (fp.startswith('res/xml/') and fp.endswith('.xml')):
                    continue
                if nsc_filename_hint not in fp:
                    continue
                try:
                    raw = a.get_file(fp)
                    if not raw:
                        continue
                    try:
                        xml_str = AXMLPrinter(raw).get_buff()
                    except Exception:
                        xml_str = raw
                    nsc_root = ET.fromstring(xml_str)
                    nsc_summary["present"] = True

                    base = nsc_root.find('base-config')
                    if base is not None:
                        bv = base.get('cleartextTrafficPermitted')
                        if bv is not None:
                            nsc_summary["base_cleartext"] = (str(bv).lower() == 'true')

                    for dcfg in nsc_root.findall('domain-config'):
                        dv = dcfg.get('cleartextTrafficPermitted')
                        domains = [d.text for d in dcfg.findall('domain') if d.text]
                        nsc_summary["domain_configs"].append({
                            "cleartext": (str(dv).lower() == 'true') if dv else None,
                            "domains":   domains,
                        })
                    break
                except Exception:
                    continue

        # NSC overrides manifest attribute when present
        effective_cleartext_allowed = manifest_cleartext_allowed
        if nsc_summary["base_cleartext"] is not None:
            effective_cleartext_allowed = nsc_summary["base_cleartext"]

        # ---- Layer 3: smali source -> sink ----
        SINK_TOKENS = {
            "WebView.loadUrl":         "Landroid/webkit/WebView;->loadUrl(",
            "WebView.loadDataBaseURL": "Landroid/webkit/WebView;->loadDataWithBaseURL(",
            "URL.openConnection":      "Ljava/net/URL;->openConnection(",
            "URL.openStream":          "Ljava/net/URL;->openStream(",
            "HttpURLConnection":       "Ljava/net/HttpURLConnection;",
            "OkHttp.newCall":          "Lokhttp3/OkHttpClient;->newCall(",
            "OkHttp.Request":          "Lokhttp3/Request",
            "Volley.StringRequest":    "Lcom/android/volley/toolbox/StringRequest;",
        }
        INVOKE_OPS = {0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78}
        NEW_INSTANCE_OP = 0x22

        url_regex = re.compile(r'^http://[^\s"\']+')

        all_http_urls   = set()
        findings        = []   # CRITICAL: http url -> sink
        orphan_urls     = []   # WARNING: http url found but no sink in same method

        for class_name, method_analysis, method in iter_app_methods(dx):
            try:
                instructions = list(method.get_instructions())
            except Exception:
                continue

            method_name = method.get_name()

            local_http_urls = []
            local_sinks     = []

            for ins in instructions:
                try:
                    op = ins.get_op_value()

                    if op in [0x1A, 0x1B]:
                        s = ins.get_string()
                        if s and url_regex.match(s):
                            url = s.strip()
                            if not is_namespace_or_example(url):
                                local_http_urls.append(url)
                                all_http_urls.add(url)
                        continue

                    if op == NEW_INSTANCE_OP:
                        out = ins.get_output() if hasattr(ins, 'get_output') else ''
                        for sink_name, token in SINK_TOKENS.items():
                            if token in out:
                                local_sinks.append(sink_name)
                                break
                        continue

                    if op in INVOKE_OPS:
                        out = ins.get_output() if hasattr(ins, 'get_output') else ''
                        for sink_name, token in SINK_TOKENS.items():
                            if token in out:
                                local_sinks.append(sink_name)
                                break

                except Exception:
                    continue

            if local_http_urls and local_sinks:
                for url in local_http_urls:
                    findings.append({
                        "class":    class_name,
                        "method":   method_name,
                        "url":      url,
                        "sinks":    sorted(set(local_sinks)),
                        "severity": "CRITICAL",
                    })
            elif local_http_urls:
                for url in local_http_urls:
                    orphan_urls.append({
                        "class":    class_name,
                        "method":   method_name,
                        "url":      url,
                        "severity": "WARNING",
                    })

        if findings:
            verdict = "CRITICAL"
        elif orphan_urls:
            verdict = "WARNING"
        elif not effective_cleartext_allowed and all_http_urls:
            verdict = "INFO"
        else:
            verdict = "PASS"

        has_finding = (verdict != "PASS")

        return jsonify({
            "verdict":                       verdict,
            "has_finding":                   has_finding,
            "manifest_cleartext_allowed":    manifest_cleartext_allowed,
            "manifest_attr_value":           manifest_attr_value,
            "effective_cleartext_allowed":   effective_cleartext_allowed,
            "target_sdk":                    target_sdk,
            "nsc_summary":                   nsc_summary,
            "findings":                      findings,
            "orphan_urls":                   orphan_urls,
            "all_http_urls":                 sorted(all_http_urls),
            "count":                         len(findings),
            "orphan_count":                  len(orphan_urls),
            "lab_id":                        "lab_001",
        }), 200

    # 4.1.2.3.6 — Weak cryptography detection (Cipher / MessageDigest)
    @app.route('/androguard/lab_060', methods=['GET'])
    def detect_lab_060():
        """
        Weak cipher detection — two independent analyses:

        (A) Cipher.getInstance(transformation) — algorithm/mode/padding
            CRITICAL: ECB / DES / RC4 / RC2 / Blowfish
            WARNING : CBC (no IV check) / 3DES (DESede)
            INFO    : GCM / CCM / ChaCha20-Poly1305
            UNKNOWN : dynamic transformation

        (B) Key material check — key+IV PAIRING to minimize false positives.
            Strategy: only flag when key source is HARDCODED. If key comes from
            KeyStore/KeyGenerator/SecureRandom, IV-only issues are downgraded.

            Key source classification (via byte[] source pattern in same method):
              HARDCODED - const-string + .getBytes() | new-array [B + fill-array-data
              KEYSTORE  - KeyGenerator.generateKey() | KeyStore.getKey()
              RANDOM    - SecureRandom.nextBytes()
              UNKNOWN   - other / parameter / field

            Severity matrix (key x iv):
              key=HARDCODED                    -> CRITICAL
                                                 (iv source recorded as metadata)
              key=KEYSTORE/RANDOM, iv=HARDCODED -> INFO
                                                 (compliance issue, not exploitable)
              key=UNKNOWN, iv=HARDCODED        -> WARNING
                                                 (manual review for key source)
              all other combinations           -> not reported (avoid noise)

        Hash functions (MessageDigest) are covered in /lab_079.

        Future work (NOT in this version):
          - Key size enforcement (RSA<2048, AES<128) via KeyGenerator.init / KeyPairGenerator.initialize
          - PBKDF2 iteration count check
          - KeyGenParameterSpec.Builder configuration audit
          - Full register-level dataflow (current is single-method heuristic)
        """
        CIPHER_TOKEN     = "Ljavax/crypto/Cipher;->getInstance("
        SECRETKEYSPEC    = "Ljavax/crypto/spec/SecretKeySpec;"
        IVPARAMETERSPEC  = "Ljavax/crypto/spec/IvParameterSpec;"
        GETBYTES_TOKEN   = "Ljava/lang/String;->getBytes("
        KEYGEN_TOKEN     = "Ljavax/crypto/KeyGenerator;->generateKey("
        KEYSTORE_TOKEN   = "Ljava/security/KeyStore;->getKey("
        SECURERAND_TOKEN = "Ljava/security/SecureRandom;->nextBytes("

        INVOKE_OPS       = {0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78}
        CONST_OPS        = {0x1A, 0x1B}
        NEW_INSTANCE_OP  = 0x22
        NEW_ARRAY_OP     = 0x23
        FILL_ARRAY_OPS   = {0x26, 0x2c}     # fill-array-data, fill-array-data-payload

        WEAK_CIPHERS = {"DES", "RC4", "ARC4", "RC2", "BLOWFISH"}
        WARN_CIPHERS = {"DESEDE", "3DES"}
        SAFE_MODES   = {"GCM", "CCM", "CHACHA20-POLY1305"}

        # ---- (A) Cipher transformation classification ----
        def parse_transformation(t):
            if not t:
                return None, None, None
            parts = [p.strip().upper() for p in t.split('/')]
            alg     = parts[0] if len(parts) >= 1 else None
            mode    = parts[1] if len(parts) >= 2 else None
            padding = parts[2] if len(parts) >= 3 else None
            return alg, mode, padding

        def classify_cipher(transformation):
            alg, mode, padding = parse_transformation(transformation)
            if alg is None:
                return "UNKNOWN", "unresolved_transformation"
            if alg in WEAK_CIPHERS:
                return "CRITICAL", "weak_algorithm:" + alg
            if mode == "ECB":
                return "CRITICAL", "ecb_mode:" + alg
            if mode in SAFE_MODES:
                return "INFO", "authenticated_encryption:" + mode
            if alg in WARN_CIPHERS:
                return "WARNING", "legacy_algorithm:" + alg
            if mode == "CBC":
                return "WARNING", "cbc_mode_no_iv_check:" + alg
            return "INFO", "unclassified:" + (alg or "?") + "/" + (mode or "default")

        # ---- (B) byte[] source classification (key+IV pairing) ----
        def classify_byte_source(instructions, target_idx, window=10):
            """Look back `window` instructions before target_idx; classify byte[] origin."""
            has_const_string = False
            has_new_array_b  = False
            has_fill_array   = False
            invokes_seen     = []

            start = max(0, target_idx - window)
            for i in range(start, target_idx):
                try:
                    ins = instructions[i]
                    op  = ins.get_op_value()
                    if op in CONST_OPS:
                        has_const_string = True
                    elif op == NEW_ARRAY_OP:
                        out = ins.get_output() if hasattr(ins, 'get_output') else ''
                        if "[B" in out:
                            has_new_array_b = True
                    elif op in FILL_ARRAY_OPS:
                        has_fill_array = True
                    elif op in INVOKE_OPS:
                        invokes_seen.append(ins.get_output() if hasattr(ins, 'get_output') else '')
                except Exception:
                    continue

            if has_new_array_b and has_fill_array:
                return "HARDCODED"
            if has_const_string and any(GETBYTES_TOKEN in inv for inv in invokes_seen):
                return "HARDCODED"
            if any(KEYGEN_TOKEN in inv or KEYSTORE_TOKEN in inv for inv in invokes_seen):
                return "KEYSTORE"
            if any(SECURERAND_TOKEN in inv for inv in invokes_seen):
                return "RANDOM"
            return "UNKNOWN"

        def find_iv_source(instructions, key_idx):
            """Scan whole method for new IvParameterSpec; classify its byte[] source.
               Returns 'NOT_USED' if no IvParameterSpec found (e.g. ECB or GCM AEAD)."""
            for idx, ins in enumerate(instructions):
                try:
                    if ins.get_op_value() != NEW_INSTANCE_OP:
                        continue
                    out = ins.get_output() if hasattr(ins, 'get_output') else ''
                    if IVPARAMETERSPEC in out:
                        # find the corresponding <init> invoke after this new-instance
                        for j in range(idx + 1, min(idx + 8, len(instructions))):
                            jins = instructions[j]
                            if jins.get_op_value() in INVOKE_OPS:
                                jout = jins.get_output() if hasattr(jins, 'get_output') else ''
                                if IVPARAMETERSPEC in jout and "-><init>" in jout:
                                    return classify_byte_source(instructions, j)
                        return classify_byte_source(instructions, idx)
                except Exception:
                    continue
            return "NOT_USED"

        cipher_findings = []
        key_findings    = []

        for class_name, method_analysis, method in iter_app_methods(dx):
            try:
                instructions = list(method.get_instructions())
            except Exception:
                continue
            method_name = method.get_name()

            # (A) scan Cipher.getInstance
            for idx, ins in enumerate(instructions):
                try:
                    if ins.get_op_value() not in INVOKE_OPS:
                        continue
                    out = ins.get_output() if hasattr(ins, 'get_output') else ''
                    if CIPHER_TOKEN not in out:
                        continue

                    arg = None
                    for back in range(1, min(6, idx + 1)):
                        prev = instructions[idx - back]
                        if prev.get_op_value() in CONST_OPS:
                            arg = prev.get_string()
                            break
                    sev, reason = classify_cipher(arg)
                    cipher_findings.append({
                        "class":          class_name,
                        "method":         method_name,
                        "transformation": arg if arg is not None else "<dynamic>",
                        "severity":       sev,
                        "reason":         reason,
                    })
                except Exception:
                    continue

            # (B) scan new SecretKeySpec, classify key source, then check IV
            method_iv_source = None   # cache per method
            for idx, ins in enumerate(instructions):
                try:
                    if ins.get_op_value() != NEW_INSTANCE_OP:
                        continue
                    out = ins.get_output() if hasattr(ins, 'get_output') else ''
                    if SECRETKEYSPEC not in out:
                        continue

                    # find the <init> invoke after this new-instance
                    init_idx = None
                    for j in range(idx + 1, min(idx + 8, len(instructions))):
                        jins = instructions[j]
                        if jins.get_op_value() in INVOKE_OPS:
                            jout = jins.get_output() if hasattr(jins, 'get_output') else ''
                            if SECRETKEYSPEC in jout and "-><init>" in jout:
                                init_idx = j
                                break
                    target_idx = init_idx if init_idx is not None else idx
                    key_source = classify_byte_source(instructions, target_idx)

                    if method_iv_source is None:
                        method_iv_source = find_iv_source(instructions, target_idx)
                    iv_source = method_iv_source

                    # Severity matrix
                    if key_source == "HARDCODED":
                        if iv_source == "HARDCODED":
                            sev    = "CRITICAL"
                            reason = "hardcoded_key_and_iv"
                        else:
                            sev    = "CRITICAL"
                            reason = "hardcoded_key"
                    elif key_source in ("KEYSTORE", "RANDOM") and iv_source == "HARDCODED":
                        sev    = "INFO"
                        reason = "hardcoded_iv_with_safe_key:" + key_source.lower()
                    elif key_source == "UNKNOWN" and iv_source == "HARDCODED":
                        sev    = "WARNING"
                        reason = "hardcoded_iv_unknown_key"
                    else:
                        # Don't report — minimize false positives
                        continue

                    key_findings.append({
                        "class":      class_name,
                        "method":     method_name,
                        "key_source": key_source,
                        "iv_source":  iv_source,
                        "severity":   sev,
                        "reason":     reason,
                    })
                except Exception:
                    continue

        all_findings = cipher_findings + key_findings
        critical = [f for f in all_findings if f["severity"] == "CRITICAL"]
        warning  = [f for f in all_findings if f["severity"] == "WARNING"]
        info     = [f for f in all_findings if f["severity"] == "INFO"]
        unknown  = [f for f in all_findings if f["severity"] == "UNKNOWN"]

        if critical:
            verdict = "CRITICAL"
        elif warning or unknown:
            verdict = "WARNING"
        elif info:
            verdict = "INFO"
        else:
            verdict = "PASS"

        return jsonify({
            "verdict":         verdict,
            "has_finding":     len(all_findings) > 0,
            "cipher_findings": cipher_findings,
            "key_findings":    key_findings,
            "critical":        critical,
            "warning":         warning,
            "info":            info,
            "unknown":         unknown,
            "count":           len(all_findings),
            "lab_id":          "lab_060",
        }), 200

    # 4.1.2.3.6 — Weak hash function detection (separate from lab_060 cipher)
    @app.route('/androguard/lab_079', methods=['GET'])
    def detect_lab_079():
        """
        Weak hash (MessageDigest) detection.
        Hash is NOT encryption: it has no key and is one-way. Kept separate
        from lab_060 (Cipher) for correct cryptographic taxonomy.

        Severity:
          CRITICAL - MD5 / MD2 / MD4 / SHA-1 (broken or collision-prone)
          INFO     - SHA-256 / SHA-384 / SHA-512 / SHA-3 (secure)
          UNKNOWN  - dynamic algorithm argument

        Future work (NOT in this version):
          - Usage classification (password hash vs file checksum vs cache key)
          - HMAC algorithm strength (Mac.getInstance pattern)
          - Iterated hashing detection (PBKDF2)
        """
        DIGEST_TOKEN = "Ljava/security/MessageDigest;->getInstance("
        INVOKE_OPS   = {0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78}
        CONST_OPS    = {0x1A, 0x1B}

        WEAK_DIGESTS = {"MD5", "MD2", "MD4", "SHA-1", "SHA1"}
        SAFE_DIGESTS = {
            "SHA-256", "SHA256", "SHA-384", "SHA384", "SHA-512", "SHA512",
            "SHA3-256", "SHA3-384", "SHA3-512",
        }

        def classify_digest(name):
            if not name:
                return "UNKNOWN", "unresolved_digest"
            n = name.strip().upper()
            if n in WEAK_DIGESTS:
                return "CRITICAL", "broken_hash:" + n
            if n in SAFE_DIGESTS:
                return "INFO", "secure_hash:" + n
            return "INFO", "unclassified_hash:" + n

        findings = []

        for class_name, method_analysis, method in iter_app_methods(dx):
            try:
                instructions = list(method.get_instructions())
            except Exception:
                continue
            method_name = method.get_name()

            for idx, ins in enumerate(instructions):
                try:
                    if ins.get_op_value() not in INVOKE_OPS:
                        continue
                    out = ins.get_output() if hasattr(ins, 'get_output') else ''
                    if DIGEST_TOKEN not in out:
                        continue

                    arg = None
                    for back in range(1, min(6, idx + 1)):
                        prev = instructions[idx - back]
                        if prev.get_op_value() in CONST_OPS:
                            arg = prev.get_string()
                            break
                    sev, reason = classify_digest(arg)
                    findings.append({
                        "class":     class_name,
                        "method":    method_name,
                        "algorithm": arg if arg is not None else "<dynamic>",
                        "severity":  sev,
                        "reason":    reason,
                    })
                except Exception:
                    continue

        critical = [f for f in findings if f["severity"] == "CRITICAL"]
        info     = [f for f in findings if f["severity"] == "INFO"]
        unknown  = [f for f in findings if f["severity"] == "UNKNOWN"]

        if critical:
            verdict = "CRITICAL"
        elif unknown:
            verdict = "WARNING"
        elif info:
            verdict = "INFO"
        else:
            verdict = "PASS"

        return jsonify({
            "verdict":     verdict,
            "has_finding": len(findings) > 0,
            "findings":    findings,
            "critical":    critical,
            "info":        info,
            "unknown":     unknown,
            "count":       len(findings),
            "lab_id":      "lab_079",
        }), 200

    # 5.2.6 — Base64-encoded sensitive content detection (replaces legacy lab_022)
    @app.route('/androguard/lab_022', methods=['GET'])
    def detect_lab_022():
        """
        Base64-encoded sensitive content detection.

        Base64 alone is NOT a vulnerability — flagging all Base64 produces
        massive false positives (icons, JWT headers, binary resources, third-party
        SDK data). This lab only flags Base64 strings whose DECODED content
        matches known risky patterns:

          CRITICAL - decoded as cleartext http:// URL
          CRITICAL - decoded matches known secret patterns
                     (AWS Access Key / Google API Key / JWT Token)
          WARNING  - decoded contains sensitive keywords
                     (password / secret / api_key / token / credential / ...)

        Everything else (random binary, normal text, non-risky content) is
        silently ignored to avoid noise.

        Conceptually this is the "Base64-encoded counterpart" of lab_074
        (hardcoded plaintext secret) — same risk patterns, different encoding.
        """
        import base64 as _b64

        BASE64_SHAPE = re.compile(r'^[A-Za-z0-9+/]{8,}={0,2}$')
        CONST_OPS    = {0x1A, 0x1B}

        SENSITIVE_KEYWORDS = [
            "password", "passwd", "secret", "api_key", "apikey",
            "token", "credential", "auth_token", "access_key",
            "private_key", "client_secret", "bearer", "authorization",
        ]
        SECRET_PATTERNS = {
            "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
            "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
            "JWT Token":      re.compile(r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+"),
        }

        # JWT header literal is itself base64 and decodes to JSON — exclude common ones
        BENIGN_DECODED_PREFIXES = (
            '{"alg":', '{"typ":',         # JWT header JSON
        )

        def classify(decoded_bytes):
            if not decoded_bytes:
                return None, None, None
            # Reject obvious binary (lots of non-printable bytes)
            try:
                text = decoded_bytes.decode('utf-8')
            except Exception:
                return None, None, None
            if not text:
                return None, None, None
            # Skip benign JWT header
            for p in BENIGN_DECODED_PREFIXES:
                if text.startswith(p):
                    return None, None, None
            # Check 1: cleartext HTTP URL
            if text.lower().startswith("http://"):
                return "CRITICAL", "decoded_http_url", text[:80]
            # Check 2: secret pattern
            for name, pat in SECRET_PATTERNS.items():
                if pat.search(text):
                    return "CRITICAL", "secret_pattern:" + name, text[:80]
            # Check 3: sensitive keyword
            low = text.lower()
            for kw in SENSITIVE_KEYWORDS:
                if kw in low:
                    return "WARNING", "sensitive_keyword:" + kw, text[:80]
            return None, None, None

        findings = []

        for class_name, method_analysis, method in iter_app_methods(dx):
            try:
                instructions = list(method.get_instructions())
            except Exception:
                continue
            method_name = method.get_name()

            for ins in instructions:
                try:
                    if ins.get_op_value() not in CONST_OPS:
                        continue
                    s = ins.get_string()
                    if not s:
                        continue
                    # Shape filter: length 8~4096, base64 charset, optional padding
                    if len(s) < 8 or len(s) > 4096:
                        continue
                    if not BASE64_SHAPE.match(s):
                        continue
                    try:
                        decoded = _b64.b64decode(s, validate=False)
                    except Exception:
                        continue
                    sev, reason, preview = classify(decoded)
                    if sev is None:
                        continue
                    findings.append({
                        "class":    class_name,
                        "method":   method_name,
                        "encoded":  s[:60],
                        "decoded":  preview,
                        "severity": sev,
                        "reason":   reason,
                    })
                except Exception:
                    continue

        critical = [f for f in findings if f["severity"] == "CRITICAL"]
        warning  = [f for f in findings if f["severity"] == "WARNING"]

        if critical:
            verdict = "CRITICAL"
        elif warning:
            verdict = "WARNING"
        else:
            verdict = "PASS"

        return jsonify({
            "verdict":     verdict,
            "has_finding": len(findings) > 0,
            "findings":    findings,
            "critical":    critical,
            "warning":     warning,
            "count":       len(findings),
            "lab_id":      "lab_022",
        }), 200

    # 4.1.5.4.2 — WebView security configuration audit (replaces legacy lab_034)
    @app.route('/androguard/lab_034', methods=['GET'])
    def detect_lab_034():
        """
        WebView security configuration audit.

        Legacy lab_034 flagged every setJavaScriptEnabled(true) which causes ~95%
        false positives — JS-enabled WebView is the standard usage. This version
        focuses on three real, modern risk patterns:

          CRITICAL - setAllowFileAccessFromFileURLs(true)
                     -> JS in WebView can read App-local files
          CRITICAL - setAllowUniversalAccessFromFileURLs(true)
                     -> JS bypasses Same-Origin Policy
          WARNING  - setJavaScriptEnabled(true) + loadUrl(variable) in same method
                     -> JS enabled while loading attacker-controllable URL (XSS)

        setJavaScriptEnabled(true) alone is NOT reported (standard usage).
        loadUrl(static_const_string_url) is NOT reported (trusted content).

        Future work (NOT in this version):
          - addJavascriptInterface + minSdkVersion check
          - setMixedContentMode MIXED_CONTENT_ALWAYS_ALLOW
          - setWebContentsDebuggingEnabled in release
          - Cross-method dataflow for loadUrl source
        """
        FILE_ACCESS_TOKEN      = "Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs("
        UNIVERSAL_ACCESS_TOKEN = "Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs("
        JS_ENABLE_TOKEN        = "Landroid/webkit/WebSettings;->setJavaScriptEnabled("
        LOAD_URL_TOKEN         = "Landroid/webkit/WebView;->loadUrl("
        INVOKE_OPS             = {0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78}
        CONST_OPS              = {0x1A, 0x1B}
        CONST_INT_OPS          = {0x12, 0x13, 0x14, 0x15}  # const/4, const/16, const, const/high16

        def get_bool_arg(instructions, idx):
            """Look back up to 5 instructions for const-int = 1 (true) or 0 (false)."""
            for back in range(1, min(6, idx + 1)):
                prev = instructions[idx - back]
                if prev.get_op_value() in CONST_INT_OPS:
                    try:
                        out = prev.get_output() if hasattr(prev, 'get_output') else ''
                        # output format: "v1, 0x1" — parse the second token
                        if "0x1" in out or " 1" in out.split(',')[-1]:
                            return True
                        if "0x0" in out or " 0" in out.split(',')[-1]:
                            return False
                    except Exception:
                        continue
            return None

        def loadurl_has_const_arg(instructions, idx):
            """Check if the loadUrl call has a const-string within 5 prev instructions."""
            for back in range(1, min(6, idx + 1)):
                prev = instructions[idx - back]
                if prev.get_op_value() in CONST_OPS:
                    return True
            return False

        findings = []

        for class_name, method_analysis, method in iter_app_methods(dx):
            try:
                instructions = list(method.get_instructions())
            except Exception:
                continue
            method_name = method.get_name()

            js_enabled        = False
            dynamic_load_url  = False    # loadUrl with variable arg (no const-string)

            for idx, ins in enumerate(instructions):
                try:
                    if ins.get_op_value() not in INVOKE_OPS:
                        continue
                    out = ins.get_output() if hasattr(ins, 'get_output') else ''

                    # CRITICAL: setAllowFileAccessFromFileURLs(true)
                    if FILE_ACCESS_TOKEN in out:
                        if get_bool_arg(instructions, idx) is True:
                            findings.append({
                                "class":    class_name,
                                "method":   method_name,
                                "api":      "setAllowFileAccessFromFileURLs(true)",
                                "severity": "CRITICAL",
                                "reason":   "js_can_read_local_files",
                            })
                        continue

                    # CRITICAL: setAllowUniversalAccessFromFileURLs(true)
                    if UNIVERSAL_ACCESS_TOKEN in out:
                        if get_bool_arg(instructions, idx) is True:
                            findings.append({
                                "class":    class_name,
                                "method":   method_name,
                                "api":      "setAllowUniversalAccessFromFileURLs(true)",
                                "severity": "CRITICAL",
                                "reason":   "js_bypass_same_origin_policy",
                            })
                        continue

                    # collect flags for the JS+dynamic-loadUrl pairing check
                    if JS_ENABLE_TOKEN in out:
                        if get_bool_arg(instructions, idx) is True:
                            js_enabled = True
                    elif LOAD_URL_TOKEN in out:
                        if not loadurl_has_const_arg(instructions, idx):
                            dynamic_load_url = True
                except Exception:
                    continue

            # WARNING: JS enabled + loadUrl(variable) in same method
            if js_enabled and dynamic_load_url:
                findings.append({
                    "class":    class_name,
                    "method":   method_name,
                    "api":      "setJavaScriptEnabled(true) + loadUrl(variable)",
                    "severity": "WARNING",
                    "reason":   "xss_dynamic_url_with_js_enabled",
                })

        critical = [f for f in findings if f["severity"] == "CRITICAL"]
        warning  = [f for f in findings if f["severity"] == "WARNING"]

        if critical:
            verdict = "CRITICAL"
        elif warning:
            verdict = "WARNING"
        else:
            verdict = "PASS"

        return jsonify({
            "verdict":     verdict,
            "has_finding": len(findings) > 0,
            "findings":    findings,
            "critical":    critical,
            "warning":     warning,
            "count":       len(findings),
            "lab_id":      "lab_034",
        }), 200

    # 4.1.2.3.11 — Sensitive data copied to system clipboard detection
    @app.route('/androguard/lab_080', methods=['GET'])
    def detect_lab_080():
        """
        Sensitive data written to the system clipboard.

        Any app (and some IMEs) can read the global clipboard. Copying secrets
        (passwords, PINs, card numbers, tokens) into it exposes them to other apps.

        Detection strategy — same-method co-occurrence (low false positive):
          1. Find a clipboard write API call:
               ClipboardManager.setPrimaryClip(ClipData)   (modern)
               ClipboardManager.setText(CharSequence)      (deprecated)
          2. Scan const-strings in the SAME method (covers the ClipData label and
             any literal hints such as "password", field names, etc.)
          3. Classify by keyword:
               CRITICAL - explicit secret keyword (password / pin / cvv / ssn / card / secret key)
               WARNING  - possibly-sensitive keyword (token / account / auth / credential / otp)
               (not reported) - clipboard write with no sensitive keyword (normal usage,
                                e.g. copying an order id or share link)

        Limitation: same-method heuristic only — no taint tracking. A secret
        assembled in another method then copied will be missed. Conversely the
        keyword is a hint, not proof the copied value is the secret.
        """
        CLIP_TOKENS = [
            "Landroid/content/ClipboardManager;->setPrimaryClip(",
            "Landroid/text/ClipboardManager;->setText(",
        ]
        INVOKE_OPS = {0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78}
        CONST_OPS  = {0x1A, 0x1B}

        CRITICAL_RE = re.compile(
            r'(password|passwd|pwd|\bpin\b|cvv|cvc|ssn|credit.?card|card.?num|secret.?key|private.?key)',
            re.IGNORECASE
        )
        WARNING_RE = re.compile(
            r'(token|account|auth|credential|\botp\b|api.?key|access.?key|session)',
            re.IGNORECASE
        )

        findings = []

        for class_name, method_analysis, method in iter_app_methods(dx):
            try:
                instructions = list(method.get_instructions())
            except Exception:
                continue
            method_name = method.get_name()

            # Pass 1: does this method write to the clipboard?
            has_clip_write = False
            for ins in instructions:
                try:
                    if ins.get_op_value() not in INVOKE_OPS:
                        continue
                    out = ins.get_output() if hasattr(ins, 'get_output') else ''
                    if any(tok in out for tok in CLIP_TOKENS):
                        has_clip_write = True
                        break
                except Exception:
                    continue

            if not has_clip_write:
                continue

            # Pass 2: collect const-strings in the same method, find the strongest keyword hit
            severity = None
            reason   = None
            matched  = None
            for ins in instructions:
                try:
                    if ins.get_op_value() not in CONST_OPS:
                        continue
                    s = ins.get_string()
                    if not s:
                        continue
                    m = CRITICAL_RE.search(s)
                    if m:
                        severity = "CRITICAL"
                        reason   = "explicit_secret_keyword"
                        matched  = m.group(0)
                        break  # CRITICAL is the strongest, stop early
                    if severity is None:
                        m2 = WARNING_RE.search(s)
                        if m2:
                            severity = "WARNING"
                            reason   = "possibly_sensitive_keyword"
                            matched  = m2.group(0)
                except Exception:
                    continue

            if severity is None:
                continue  # clipboard write with no sensitive keyword -> not reported

            findings.append({
                "class":    class_name,
                "method":   method_name,
                "keyword":  matched,
                "severity": severity,
                "reason":   reason,
            })

        critical = [f for f in findings if f["severity"] == "CRITICAL"]
        warning  = [f for f in findings if f["severity"] == "WARNING"]

        if critical:
            verdict = "CRITICAL"
        elif warning:
            verdict = "WARNING"
        else:
            verdict = "PASS"

        return jsonify({
            "verdict":     verdict,
            "has_finding": len(findings) > 0,
            "findings":    findings,
            "critical":    critical,
            "warning":     warning,
            "count":       len(findings),
            "lab_id":      "lab_080",
        }), 200

    # 4.1.5.4.1 — 行動應用程式應針對使用者於輸入階段之字串，進行安全檢查
    @app.route('/androguard/lab_081', methods=['GET'])
    def detect_lab_081():
        """
        4.1.5.4.1 使用者輸入驗證 (型別/長度)

        掃 res/layout* 的 EditText/AutoCompleteTextView, 檢查 inputType (型別)
        跟 maxLength (長度, 只查密碼/敏感欄位)。

        WARNING = 敏感欄位缺型別或長度限制; NOTICE = 一般欄位缺型別限制。
        只查得到 layout XML 宣告, 程式碼裡的 InputFilter 跟 Compose UI 掃不到。
        """
        try:
            from androguard.core.axml import AXMLPrinter        # androguard 4.x
        except ImportError:
            from androguard.core.bytecodes.axml import AXMLPrinter  # androguard 3.x
        import xml.etree.ElementTree as ET

        ANDROID_NS = '{http://schemas.android.com/apk/res/android}'

        # 敏感欄位命名關鍵字 (與 lab_072 同一套)
        SENSITIVE_RE = re.compile(
            r'(password|passwd|pwd|pin\b|cvv|cvc|ssn|credit.?card|card.?num|'
            r'otp|token|secret|auth.?code|account.?num)',
            re.IGNORECASE
        )

        # inputType 在編譯後的 layout 是位元遮罩整數, 以下對照表用來還原成 XML 原本的寫法
        # (對照 Android TextView 文件的 android:inputType 取值)
        TYPE_MASK_CLASS     = 0x0000000f
        TYPE_MASK_VARIATION = 0x00000ff0
        TYPE_CLASS_TEXT     = 0x01
        TYPE_CLASS_NUMBER   = 0x02
        TYPE_CLASS_PHONE    = 0x03
        TYPE_CLASS_DATETIME = 0x04
        TEXT_VARIATIONS = {
            0x00: 'text',                0x10: 'textUri',
            0x20: 'textEmailAddress',    0x30: 'textEmailSubject',
            0x40: 'textShortMessage',    0x50: 'textLongMessage',
            0x60: 'textPersonName',      0x70: 'textPostalAddress',
            0x80: 'textPassword',        0x90: 'textVisiblePassword',
            0xa0: 'textWebEditText',     0xb0: 'textFilter',
            0xc0: 'textPhonetic',        0xd0: 'textWebEmailAddress',
            0xe0: 'textWebPassword',
        }
        NUMBER_VARIATIONS   = {0x00: 'number', 0x10: 'numberPassword'}
        DATETIME_VARIATIONS = {0x00: 'datetime', 0x10: 'date', 0x20: 'time'}
        TEXT_FLAGS = [
            (0x001000, 'textCapCharacters'), (0x002000, 'textCapWords'),
            (0x004000, 'textCapSentences'),  (0x008000, 'textAutoCorrect'),
            (0x010000, 'textAutoComplete'),  (0x020000, 'textMultiLine'),
            (0x040000, 'textImeMultiLine'),  (0x080000, 'textNoSuggestions'),
        ]
        NUMBER_FLAGS = [(0x001000, 'numberSigned'), (0x002000, 'numberDecimal')]

        def describe_input_type(raw_val):
            """位元遮罩還原成 XML 寫法 (0x81 -> "textPassword"), 供報告顯示與密碼欄位判斷"""
            if raw_val is None:
                return None
            try:
                v = int(raw_val, 0) if isinstance(raw_val, str) else int(raw_val)
            except (ValueError, TypeError):
                return str(raw_val)

            input_class = v & TYPE_MASK_CLASS
            variation   = v & TYPE_MASK_VARIATION
            parts       = []

            if input_class == TYPE_CLASS_TEXT:
                parts.append(TEXT_VARIATIONS.get(variation, 'text'))
                parts += [n for bit, n in TEXT_FLAGS if v & bit]
            elif input_class == TYPE_CLASS_NUMBER:
                parts.append(NUMBER_VARIATIONS.get(variation, 'number'))
                parts += [n for bit, n in NUMBER_FLAGS if v & bit]
            elif input_class == TYPE_CLASS_PHONE:
                parts.append('phone')
            elif input_class == TYPE_CLASS_DATETIME:
                parts.append(DATETIME_VARIATIONS.get(variation, 'datetime'))
            elif input_class == 0x00:
                parts.append('none')
            else:
                return '0x%08x' % v

            # 變體是預設值又帶旗標時省略基底名 — XML 寫的是 "numberDecimal" 而非 "number|numberDecimal"
            if len(parts) > 1 and variation == 0x00 and parts[0] in ('text', 'number'):
                parts = parts[1:]

            return '|'.join(parts)

        def is_password_field(raw_val):
            # textPassword / textVisiblePassword / textWebPassword / numberPassword
            return 'Password' in (describe_input_type(raw_val) or '')

        def is_edittext_tag(tag):
            # 完整類別名只取簡名; AutoCompleteTextView 系列是 EditText 的子類別, 一併納入
            simple_name = (tag.split('}')[-1] if '}' in tag else tag).split('.')[-1]
            return simple_name.endswith(('EditText', 'AutoCompleteTextView'))

        def make_field_label(hint_val, id_val, ordinal):
            """欄位定位標籤, 依可讀性取 hint > id > 元素出現順序"""
            if hint_val and not hint_val.startswith('@'):
                return 'hint="%s"' % hint_val
            if id_val:
                return 'id=%s' % id_val
            return 'field #%d' % ordinal

        # 註: findings 內會被印進報告 Detail 的字串一律用英文 —— 中文版與英文版報告
        # 共用同一份 vector_details, 寫中文會導致英文版報告也印出中文。
        findings     = []
        layout_files = [f for f in a.get_files() if f.endswith('.xml')
                        and (f.startswith('res/layout/') or f.startswith('res/layout-'))]
        total_fields = 0

        for layout_file in layout_files:
            try:
                root = ET.fromstring(AXMLPrinter(a.get_file(layout_file)).get_buff())
            except Exception:
                continue

            field_ordinal = 0          # 該 layout 檔內第幾個輸入欄位 (供無 hint/id 時定位)
            for elem in root.iter():
                if not is_edittext_tag(elem.tag):
                    continue

                total_fields  += 1
                field_ordinal += 1

                hint       = elem.get(ANDROID_NS + 'hint', '')
                elem_id    = elem.get(ANDROID_NS + 'id', '')
                input_type = elem.get(ANDROID_NS + 'inputType')
                max_length = elem.get(ANDROID_NS + 'maxLength')

                is_sensitive = (is_password_field(input_type)
                                or bool(SENSITIVE_RE.search(hint + ' ' + elem_id)))

                missing = []
                if input_type is None:
                    missing.append("inputType (type constraint)")
                if max_length is None and is_sensitive:
                    missing.append("maxLength (length constraint)")

                if not missing:
                    continue   # 應檢查的限制皆已宣告 -> 視為符合

                findings.append({
                    "file":        layout_file,
                    "tag":         (elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag).split('.')[-1],
                    "hint":        hint,
                    "id":          elem_id,
                    "field_label": make_field_label(hint, elem_id, field_ordinal),
                    "input_type":  input_type,
                    "input_type_readable": describe_input_type(input_type),
                    "max_length":  max_length,
                    "missing":     missing,
                    "severity":    "WARNING" if is_sensitive else "NOTICE",
                })

        return jsonify({
            "has_finding":        len(findings) > 0,
            "count":              len(findings),
            "results":            findings,
            "warning":            [f for f in findings if f["severity"] == "WARNING"],
            "notice":             [f for f in findings if f["severity"] == "NOTICE"],
            "total_input_fields": total_fields,
            "scanned_layouts":    len(layout_files),
            # 完全沒有字串輸入介面 -> 依官方檢測結果規定視為符合
            "no_input_interface": total_fields == 0,
            "lab_id":             "lab_081",
            "description":        "User input validation: EditText fields missing inputType (type) or maxLength (length) constraints"
        }), 200

    # 4.1.2.3.7 — WebView advanced configuration audit (complements lab_034)
    @app.route('/androguard/lab_065', methods=['GET'])
    def detect_lab_065():
        """
        WebView advanced configuration audit. Complements lab_034 (which covers
        setAllowFileAccessFromFileURLs / setAllowUniversalAccessFromFileURLs +
        JS+dynamic-loadUrl). This lab covers the REMAINING dangerous WebView
        setters — zero overlap with lab_034:

          WARNING - setAllowFileAccess(true)
                    WebView can load file:// URLs (default true on API<30, false
                    on API30+). Combined with a file-load entry point it enables
                    local file access. NOTE: this is a DIFFERENT api from
                    setAllowFileAccessFromFileURLs (covered by lab_034).
          WARNING - setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW = 0)
                    HTTPS page may load HTTP sub-resources -> MITM / content injection.
          WARNING - setWebContentsDebuggingEnabled(true)
                    Remote Chrome DevTools debugging; must be disabled in release.
                    Only literal `true` is flagged; a dynamic arg such as
                    BuildConfig.DEBUG is treated as a safe (debug-only) pattern.

        Static analysis cannot tell release vs debug build, so all three are
        WARNING (manual review recommended).
        """
        # token uses trailing "(" so setAllowFileAccess( does NOT match
        # setAllowFileAccessFromFileURLs( (that one continues with "FromFileURLs")
        FILE_ACCESS_TOKEN = "Landroid/webkit/WebSettings;->setAllowFileAccess("
        MIXED_TOKEN       = "Landroid/webkit/WebSettings;->setMixedContentMode("
        DEBUG_TOKEN       = "Landroid/webkit/WebView;->setWebContentsDebuggingEnabled("

        INVOKE_OPS    = {0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78}
        CONST_INT_OPS = {0x12, 0x13, 0x14, 0x15}  # const/4, const/16, const, const/high16
        MIXED_CONTENT_ALWAYS_ALLOW = 0

        def get_const_int(instructions, idx):
            """Look back up to 5 instructions; return the int value of the nearest
               const-int, or None if not a literal const."""
            for back in range(1, min(6, idx + 1)):
                prev = instructions[idx - back]
                if prev.get_op_value() in CONST_INT_OPS:
                    out = prev.get_output() if hasattr(prev, 'get_output') else ''
                    tok = out.split(',')[-1].strip()
                    try:
                        if tok.lower().startswith('0x') or tok.lower().startswith('-0x'):
                            return int(tok, 16)
                        return int(tok)
                    except Exception:
                        return None
            return None

        findings = []

        for class_name, method_analysis, method in iter_app_methods(dx):
            try:
                instructions = list(method.get_instructions())
            except Exception:
                continue
            method_name = method.get_name()

            for idx, ins in enumerate(instructions):
                try:
                    if ins.get_op_value() not in INVOKE_OPS:
                        continue
                    out = ins.get_output() if hasattr(ins, 'get_output') else ''

                    if FILE_ACCESS_TOKEN in out:
                        if get_const_int(instructions, idx) == 1:
                            findings.append({
                                "class":    class_name,
                                "method":   method_name,
                                "api":      "setAllowFileAccess(true)",
                                "severity": "WARNING",
                                "reason":   "webview_can_load_file_urls",
                            })
                    elif MIXED_TOKEN in out:
                        if get_const_int(instructions, idx) == MIXED_CONTENT_ALWAYS_ALLOW:
                            findings.append({
                                "class":    class_name,
                                "method":   method_name,
                                "api":      "setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)",
                                "severity": "WARNING",
                                "reason":   "https_page_loads_http_subresources",
                            })
                    elif DEBUG_TOKEN in out:
                        if get_const_int(instructions, idx) == 1:
                            findings.append({
                                "class":    class_name,
                                "method":   method_name,
                                "api":      "setWebContentsDebuggingEnabled(true)",
                                "severity": "WARNING",
                                "reason":   "remote_debug_must_be_off_in_release",
                            })
                except Exception:
                    continue

        warning = [f for f in findings if f["severity"] == "WARNING"]
        verdict = "WARNING" if warning else "PASS"

        return jsonify({
            "verdict":     verdict,
            "has_finding": len(findings) > 0,
            "findings":    findings,
            "warning":     warning,
            "count":       len(findings),
            "lab_id":      "lab_065",
        }), 200

    @app.route('/androguard/lab_057', methods=['GET'])
    def detect_lab_057():
        """
        Sensitive device / subscriber identifier reads via TelephonyManager.

        The legacy lab only matched getDeviceId(). Modern spyware reads the
        identifier through newer / more targeted APIs, so this audits all of:

          getDeviceId()        - IMEI/MEID (legacy, deprecated since API 26)
          getImei()            - IMEI            (API 26+)
          getMeid()            - MEID            (CDMA, API 26+)
          getSubscriberId()    - IMSI            (SIM subscriber id; identifies
                                                  the user even across device reset)
          getLine1Number()     - phone number
          getSimSerialNumber() - SIM serial (ICC ID)

        Reading any of these is a hardware / subscriber identifier access that
        needs a privacy justification (Android 10+ requires privileged
        permission), so each is reported as WARNING for manual review.
        Presence-based: the read itself is the privacy concern, regardless of
        whether the value is later transmitted.
        """
        TARGETS = {
            "Landroid/telephony/TelephonyManager;->getDeviceId(":        ("getDeviceId()",        "imei_meid_legacy"),
            "Landroid/telephony/TelephonyManager;->getImei(":            ("getImei()",            "imei"),
            "Landroid/telephony/TelephonyManager;->getMeid(":            ("getMeid()",            "meid"),
            "Landroid/telephony/TelephonyManager;->getSubscriberId(":    ("getSubscriberId()",    "imsi_subscriber_id"),
            "Landroid/telephony/TelephonyManager;->getLine1Number(":     ("getLine1Number()",     "phone_number"),
            "Landroid/telephony/TelephonyManager;->getSimSerialNumber(": ("getSimSerialNumber()", "sim_serial_iccid"),
        }

        INVOKE_OPS = {0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78}

        findings = []
        seen = set()  # de-dup identical (class, method, api)

        for class_name, method_analysis, method in iter_app_methods(dx):
            try:
                instructions = list(method.get_instructions())
            except Exception:
                continue
            try:
                method_name = method.get_name()
            except Exception:
                method_name = getattr(method_analysis, 'name', '') or ''

            for ins in instructions:
                try:
                    if ins.get_op_value() not in INVOKE_OPS:
                        continue
                    out = ins.get_output() if hasattr(ins, 'get_output') else ''
                    for token, (api, reason) in TARGETS.items():
                        if token in out:
                            key = (class_name, method_name, api)
                            if key in seen:
                                continue
                            seen.add(key)
                            findings.append({
                                "class":    class_name,
                                "method":   method_name,
                                "api":      api,
                                "severity": "WARNING",
                                "reason":   reason,
                            })
                except Exception:
                    continue

        warning = [f for f in findings if f["severity"] == "WARNING"]
        verdict = "WARNING" if warning else "PASS"

        return jsonify({
            "verdict":     verdict,
            "has_finding": len(findings) > 0,
            "findings":    findings,
            "warning":     warning,
            "count":       len(findings),
            "lab_id":      "lab_057",
        }), 200

    @app.route('/androguard/lab_058', methods=['GET'])
    def detect_lab_058():
        """
        Reads of Settings.Secure.ANDROID_ID - a device-scoped identifier used
        for fingerprinting / user tracking.

        Settings.Secure.ANDROID_ID is a compile-time String constant inlined as
        the literal "android_id", so the signal is a getString(...) call whose
        key argument is "android_id". We confirm via const-string lookback so
        that other Settings.Secure reads (e.g. "bluetooth_name") are NOT flagged
        - this preserves the precision of the old taint-based detection.
        """
        GETSTRING_TOKEN = "Landroid/provider/Settings$Secure;->getString("
        ANDROID_ID_KEY  = "android_id"

        INVOKE_OPS       = {0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78}
        CONST_STRING_OPS = {0x1a, 0x1b}  # const-string, const-string/jumbo

        def has_android_id_arg(instructions, idx):
            """Look back up to 8 instructions for a const-string == "android_id"."""
            for back in range(1, min(9, idx + 1)):
                prev = instructions[idx - back]
                if prev.get_op_value() in CONST_STRING_OPS:
                    out = prev.get_output() if hasattr(prev, 'get_output') else ''
                    lit = out.split(',', 1)[-1].strip().strip('"').strip("'")
                    if lit == ANDROID_ID_KEY:
                        return True
            return False

        findings = []
        seen = set()

        for class_name, method_analysis, method in iter_app_methods(dx):
            try:
                instructions = list(method.get_instructions())
            except Exception:
                continue
            try:
                method_name = method.get_name()
            except Exception:
                method_name = getattr(method_analysis, 'name', '') or ''

            for idx, ins in enumerate(instructions):
                try:
                    if ins.get_op_value() not in INVOKE_OPS:
                        continue
                    out = ins.get_output() if hasattr(ins, 'get_output') else ''
                    if GETSTRING_TOKEN in out and has_android_id_arg(instructions, idx):
                        key = (class_name, method_name)
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append({
                            "class":    class_name,
                            "method":   method_name,
                            "api":      "Settings.Secure.getString(ANDROID_ID)",
                            "severity": "WARNING",
                            "reason":   "android_id_device_fingerprint",
                        })
                except Exception:
                    continue

        warning = [f for f in findings if f["severity"] == "WARNING"]
        verdict = "WARNING" if warning else "PASS"

        return jsonify({
            "verdict":     verdict,
            "has_finding": len(findings) > 0,
            "findings":    findings,
            "warning":     warning,
            "count":       len(findings),
            "lab_id":      "lab_058",
        }), 200

    app.run(host='0.0.0.0', port=port)
if __name__ == "__main__":
    os.makedirs("./uploads", exist_ok=True)
    apk_env = os.environ.get('APK_PATH', None)
    run_androguard_server(8010, apk_env)
