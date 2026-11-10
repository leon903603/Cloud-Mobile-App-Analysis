import os
import re
import time
import zipfile
import json
import subprocess
import base64
import math
import urllib.request
import urllib.error
import urllib.parse
import concurrent.futures
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

    # 共用函式 / 常數 (iter_app_methods、app_class_filter 等) 在所有 lab 端點之後、app.run 之前

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

        STORAGE_RESULT_CACHE.clear()
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
    # 4.1.5.3.1 — 函式庫引用安全
    @app.route('/androguard/lab_016', methods=['GET'])
    def detect_lab_016():
        """
        風險: 引用有已知漏洞的函式庫, 攻擊者可直接利用公開漏洞。
        檢測: 辨識函式庫名稱與版本: Java (META-INF/*.version、Google *.properties、pom.properties; 沒有版本檔的常見函式庫
              從 DEX 類別辨識、從字串取版本)、網頁 (assets / React Native bundle 的 JavaScript, Retire.js 規則與內嵌 package.json)、
              .NET 組件 (版本資源)、Flutter 套件 (libapp.so 的套件名稱)、.so 與 Unity 引擎的版本字串;
              Java / 網頁 / .NET / Flutter 用 OSV 查詢、.so 與 Unity 用 NVD CPE 查詢; libwebp 另用符號比對 CVE-2023-4863。
        結果: 有 CVE 且 CVSS v3.0 >= 7 (只有 v3.1 的用 v3.0 公式重算; 前 LIB_MAX_NVD_CONFIRM 個用 NVD 分數確認) -> WARNING; 查詢失敗、CVE 沒有 v3 分數、完全辨識不到函式庫,
              或有引用函式庫但讀不到版本、且該函式庫有 CVSS >= 7 的漏洞版本 -> NOT_EVALUATED (列出受影響版本); 其他 -> PASS。
              加殼看不到程式碼、網頁程式碼加密、或混淆把 class 搬到短套件 (函式庫認不出來) -> NOT_EVALUATED, 請提供未加殼 / 未混淆的 APK;
              .NET 組件被壓縮 -> NOT_EVALUATED。
              沒有版本記錄的 Java 函式庫用類別名稱到 Maven Central 反查, 版本另讀函式庫的 BuildConfig.VERSION_NAME;
              框架本身: React Native (ReactNativeVersion)、Cordova (cordova.js); 沒有版本字串的 .so 用匯出函式名稱 / 檔名對到 NVD 產品,
              兩者讀不到版本, 有高風險 CVE 就 NOT_EVALUATED。
        限制: 網頁只認 LIB_JS_SIGNATURES 與內嵌 package.json; Flutter 套件沒有版本; App 自己的 .so 與 NVD 沒有的產品認不出來。
        """
        return jsonify(dict(library_vuln_result(a, d), lab_id="lab_016",
                            description="Referenced library known vulnerability check (CVE with CVSS v3 >= 7)")), 200

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


    # 簽章完整性檢查 (防竄改 / 重新打包)
    @app.route('/androguard/lab_026', methods=['GET'])
    def detect_lab_026():
        """
        風險: App 沒驗證自身簽章, 被重新打包 (植入惡意碼後重簽) 仍可正常執行。
        檢測: App 自己的程式碼讀取 PackageInfo.signatures / signingInfo、
              SigningInfo 的簽章清單或 PackageManager.hasSigningCertificate,
              或 App 自己有呼叫 Play Integrity / SafetyNet / 已知 RASP SDK -> 視為有做 (只打包沒呼叫不算)。
        結果: 都沒有 -> WARNING (缺少防護)。
        限制: 簽章比對寫在 .so、反射呼叫或只在伺服器端驗證者看不到。
        """
        keep = app_class_filter(a)
        code_evidence = strip_instructions(find_app_references(dx, keep, [
            "Landroid/content/pm/PackageInfo;->signatures",
            "Landroid/content/pm/PackageInfo;->signingInfo",
            "Landroid/content/pm/SigningInfo;->getApkContentsSigners",
            "Landroid/content/pm/SigningInfo;->getSigningCertificateHistory",
            "Landroid/content/pm/PackageManager;->hasSigningCertificate",
        ]))
        api_evidence = find_app_sdk_calls(dx, keep, PLAY_INTEGRITY_PREFIXES + RASP_SDK_PREFIXES)
        return protection_result("lab_026", "App signature integrity check implementation",
                                 code_evidence, api_evidence, keep)

    # 4.1.2.3.9 — 防止螢幕擷取 (FLAG_SECURE)
    @app.route('/androguard/lab_027', methods=['GET'])
    def detect_lab_027():
        """
        風險: 畫面可被截圖 / 錄影 / 顯示在最近使用畫面, 敏感資料外洩。
        檢測: App 自己的程式碼呼叫 Window.addFlags(flags) / setFlags(flags, mask) 且傳入的常數含
              FLAG_SECURE (0x2000) 位元, 或呼叫 SurfaceView.setSecure(true)。
              追蹤的是「實際傳入的參數暫存器」最近一次被設定的值, 避免附近無關的常數 (-1、8192 緩衝區大小) 造成誤判。
              再往上追呼叫路徑, 看涵蓋哪些 Activity (第三方 SDK 的畫面和 Dialog 不算)。
        結果: 所有 Activity 都確定有設 -> PASS;
              完全沒防護、看得到的 Activity 確定沒設、只有警示或只有切換畫面遮蔽 -> WARNING;
              有條件才設、只有 SurfaceView.setSecure (只保護該元件)、值要執行時才知道、追不到涵蓋哪些頁面、有 Activity 不在 dex 裡、有警示加切換畫面遮蔽、
              看不到 App 程式碼 (如加殼) -> NOT_EVALUATED。
        限制: 寫在 Flutter / RN 等框架層的設定看不到; 不顯示畫面的 Activity 也會算一頁。
        """
        FLAG_SECURE = 0x2000
        # 第一個運算元是「讀取」而不是「寫入」的指令, 往回找時要跳過
        NOT_WRITING = ("invoke", "if-", "iput", "sput", "aput", "return", "throw", "goto",
                       "fill-", "monitor", "packed-", "sparse-", "check-cast")

        def arg_registers(out):
            """invoke 的參數暫存器: 'v4, v5, L...' 或 range 格式 'v0 ... v2, L...'"""
            head = out.split("L", 1)[0]
            m = re.match(r"\s*v(\d+) \.\.\. v(\d+)", head)
            if m:
                return ["v%d" % i for i in range(int(m.group(1)), int(m.group(2)) + 1)]
            return re.findall(r"v\d+", head)

        def reg_value(instructions, index, reg, window=30):
            """往回找最近一次寫入 reg 的指令: 常數回傳數值, 其他 (變數 / 欄位 / 運算結果) 回傳 None"""
            for ins in reversed(instructions[max(0, index - window):index]):
                name = ins.get_name()
                if name.startswith(NOT_WRITING):
                    continue
                out = ins.get_output()
                if out != reg and not out.startswith(reg + ","):
                    continue
                if name.startswith("const") and "string" not in name and "class" not in name:
                    # androguard 輸出的已是實際數值 (const/high16 也已還原位移)
                    try:
                        return int(out.split(",")[-1].strip(), 0)
                    except ValueError:
                        return None
                if name.startswith("or-int/lit"):  # flags = x | FLAG_SECURE
                    try:
                        return int(out.split(",")[-1].strip(), 0)
                    except ValueError:
                        return None
                return None
            return None

        def sets_flag_secure(ref):
            regs = arg_registers(ref["instructions"][ref["index"]].get_output())
            if len(regs) < 2:
                return False
            value = lambda k: reg_value(ref["instructions"], ref["index"], regs[k]) if len(regs) > k else None
            flags = value(1)
            if ref["api"].endswith("setSecure"):
                return flags == 1
            if flags is None or not flags & FLAG_SECURE:
                return False
            if ref["api"].endswith("setFlags"):
                mask = value(2)
                return mask is None or bool(mask & FLAG_SECURE)
            return True

        def may_set_flag_secure(ref):
            """往回找整個 method: 值算不出來、或常數可能設定 FLAG_SECURE (setFlags 的 mask 確定不含就不可能設定)"""
            regs = arg_registers(ref["instructions"][ref["index"]].get_output())
            if len(regs) < 2:
                return False
            value = lambda k: reg_value(ref["instructions"], ref["index"], regs[k], ref["index"])
            flags = value(1)
            if ref["api"].endswith("setSecure"):
                return flags is None or flags == 1
            if flags is not None and not flags & FLAG_SECURE:
                return False
            if ref["api"].endswith("setFlags") and len(regs) > 2:
                mask = value(2)
                return mask is None or bool(mask & FLAG_SECURE)
            return True

        def is_conditional(ref):
            """呼叫前有分支 (window 的 null 檢查不算) -> 可能不會執行"""
            instructions = ref["instructions"]
            for i, ins in enumerate(instructions[:ref["index"]]):
                name = ins.get_name()
                if "switch" in name:
                    return True
                if not name.startswith("if-"):
                    continue
                # getWindow() 的結果緊接著做 null 檢查才放行, 不能只比暫存器編號 (同一個暫存器可能先放別的值)
                reg = ins.get_output().split(",")[0]
                is_window_check = (name in ("if-eqz", "if-nez") and i >= 2
                                   and instructions[i - 1].get_name().startswith("move-result-object")
                                   and instructions[i - 1].get_output().strip() == reg
                                   and "->getWindow()" in instructions[i - 2].get_output())
                if not is_window_check:
                    return True
            return False

        def clears_flag_secure(ref):
            regs = arg_registers(ref["instructions"][ref["index"]].get_output())
            if len(regs) < 2:
                return False
            flags = reg_value(ref["instructions"], ref["index"], regs[1], ref["index"])
            return flags is None or bool(flags & FLAG_SECURE)

        def disables_recents_screenshot(ref):
            regs = arg_registers(ref["instructions"][ref["index"]].get_output())
            return len(regs) >= 2 and reg_value(ref["instructions"], ref["index"], regs[1], ref["index"]) in (None, 0)

        def on_dialog(ref):
            """Dialog 的 Window 不算頁面"""
            if "Dialog" in ref["class"]:
                return True
            for ins in reversed(ref["instructions"][:ref["index"]]):
                out = ins.get_output()
                if "->getWindow()" in out:
                    return "Dialog" in out
            return False

        keep = app_class_filter(a)
        refs = [r for r in find_app_references(dx, keep, [
            "Landroid/view/Window;->setFlags",
            "Landroid/view/Window;->addFlags",
            "Landroid/view/SurfaceView;->setSecure",
        ]) if not on_dialog(r)]
        # SurfaceView.setSecure 只保護該元件, 不代表整頁有保護 -> 只能算可能涵蓋 (NOT_EVALUATED)
        secure = [r for r in refs if not r["api"].endswith("setSecure") and sets_flag_secure(r)]
        unknown = [r for r in refs if r not in secure and may_set_flag_secure(r)]
        unknown += [r for r in find_app_references(dx, keep, ["Landroid/view/Window;->clearFlags"]) if clears_flag_secure(r)]
        recents = [r for r in find_app_references(dx, keep, [";->setRecentsScreenshotEnabled"]) if disables_recents_screenshot(r)]
        warnings = find_app_references(dx, keep, [";->registerScreenCaptureCallback"])
        warnings += [r for r in find_app_references(dx, keep, [";->registerContentObserver"])
                     if any("MediaStore$Images$Media;->EXTERNAL_CONTENT_URI" in i.get_output() for i in r["instructions"])
                     and ("screenshot" in r["class"].lower() or "capture" in r["class"].lower())]   # 相簿等也會監聽媒體庫, 不算警示
        verdict, reason, review, pages = screen_capture_verdict(a, dx, keep, secure, is_conditional, unknown, recents, warnings)
        return protection_result("lab_027", "Screen capture prevention (FLAG_SECURE) implementation",
                                 strip_instructions(secure) if verdict == "PASS" else [], [], keep,
                                 reason=reason, review=review, verdict=verdict, extra={"pages": pages})


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

    # 4.1.2.5.1 — 分享聲明
    @app.route('/androguard/lab_039', methods=['GET'])
    def detect_lab_039():
        """
        風險: App 自動把資料交給其他 App, 沒告知也沒同意。
        檢測: 自動分享管道 (見 find_auto_share_channels) 往上追呼叫路徑, 沒經過同意對話框也沒讀分享開關 -> 有問題。
              開啟畫面、分享選單、拍照等使用者看得到的操作不算; 分享開關只認 key 名稱像分享 / 同意的設定。
        結果: 確定送出敏感資料的管道有問題 -> WARNING;
              看不出是否敏感、接收者不明、程式碼看不到、開關 key 看不出來 -> NOT_EVALUATED (報告顯示 Not evaluated); 都沒有 -> PASS。
        限制: 敏感資料只看 extra key、欄位字串與敏感資料 API; 只追 4 層呼叫; 跨 method 組的 intent、Compose 對話框、.so 看不到。
        """
        keep = app_class_filter(a)
        channels = find_auto_share_channels(a, dx, keep)
        for c in channels:
            ev = c["evidence"]
            c["problem"] = None
            if not (ev["dialog"] or ev["switch"]):
                c["problem"] = "no consent dialog or user switch"
                if ev["switch_unverified"]:
                    c["problem"], c["unverified"] = "a setting is read on the path but its key cannot be identified", True
        return share_check_result(
            "lab_039", "Data sharing notice check (automatic sharing channels without consent)", channels, dx, keep)

    # 4.1.2.5.2 — 拒絕分享
    @app.route('/androguard/lab_040', methods=['GET'])
    def detect_lab_040():
        """
        風險: 使用者無法拒絕 App 的自動分享。
        檢測: 同 lab_039 的自動分享管道, 往上追呼叫路徑: 1. 有沒有讀分享開關 2. 讀到的值有沒有拿來決定要不要分享;
              只有同意對話框沒有開關 = 同意後無法撤回, 也算有問題。
              另記錄開關名稱、預設值、設定頁有沒有這個開關 (只放報告細節, 不影響判定)。
        結果: 確定送出敏感資料的管道沒有開關或開關沒拿來判斷 -> WARNING;
              開關的值傳到別處判斷 (看不到)、開關 key 看不出來、看不出是否敏感或管道不確定 -> NOT_EVALUATED; 都沒有 -> PASS。
        限制: 開關只認 key 名稱 (share、consent 等); DataStore 只能確認有讀, 看不到判斷。
        """
        keep = app_class_filter(a)
        channels = find_auto_share_channels(a, dx, keep)
        for c in channels:
            ev = c["evidence"]
            c["problem"] = None
            if not ev["switch"] and ev["switch_unverified"]:
                c["problem"], c["unverified"] = "a setting is read on the path but its key cannot be identified", True
            elif not ev["switch"]:
                c["problem"] = "no user switch"
            elif ev["gating"] == "none":
                c["problem"] = "user switch is read but not used to decide"
            elif ev["gating"] == "unknown":
                c["problem"], c["unverified"] = "user switch value is used elsewhere, effect not verified", True
        return share_check_result(
            "lab_040", "Data sharing refusal check (automatic sharing channels without an effective user switch)",
            channels, dx, keep)

    # 4.1.1.1.2 — 發布說明
    @app.route('/androguard/lab_041', methods=['GET'])
    def detect_lab_041():
        """
        風險: 用到的敏感資料沒在 Google Play「資料安全性」聲明。
        檢測: 1. App 自己讀取敏感資料 (有權限 + 真的讀取) 且自己有發網路請求;
              2. 有會收集資料的第三方 SDK (本身就會傳出)
              -> 去 Google Play 查該類別有沒有聲明。
        結果: 確定的資料沒聲明 -> WARNING; 查不到頁面, 或沒聲明的只有待確認的 (相機可能只掃碼、SDK 已關閉收集、
              有 INTERNET 權限但 App 程式碼看不到網路請求) -> NOT_EVALUATED (報告顯示 Not evaluated); 其他 -> PASS。
        限制: 沒追蹤資料流, App 有發網路請求就當作資料會傳出; SDK 只認清單內的。
        """
        keep = app_class_filter(a)
        package = a.get_package() or ""
        network, usages = find_sensitive_data_usage(a, dx, keep)
        result = {
            "package": package, "network": network, "usages": usages,
            "lab_id": "lab_041",
            "description": "Release notes check (Google Play Data safety vs sensitive data used in code)",
        }
        # App 自己讀的資料要有網路才算會傳出; SDK 本身就會傳出
        checked = [u for u in usages if network or u["kind"] == "sdk"]
        # 有 INTERNET 權限卻看不到網路請求 (可能經由函式庫或看不到的程式碼送出) -> 這些資料無法判定, 交給人工
        unseen = [dict(u, review="network requests not found in app code") for u in usages
                  if u["kind"] == "app" and not network and "android.permission.INTERNET" in a.get_permissions()]
        if not checked:
            result.update(verdict="NOT_EVALUATED" if unseen else "PASS", has_finding=False,
                          status="network_not_found" if unseen else ("no_sensitive_data" if not usages else "no_network"),
                          declared=[], undeclared=[], review=unseen)
            return jsonify(result), 200

        store = fetch_play_data_safety(package)
        if store["status"] != "ok":
            # 查不到不代表沒聲明, 交給人工
            result.update(verdict="NOT_EVALUATED", has_finding=False, status=store["status"],
                          declared=[], undeclared=[], review=checked + unseen)
            return jsonify(result), 200

        declared = {c.lower() for c in store["declared"]}
        missing = [u for u in checked + unseen if not all(c.lower() in declared for c in u["categories"])]
        undeclared = [u for u in missing if not u.get("review")]
        review = [u for u in missing if u.get("review")]
        result.update(verdict="WARNING" if undeclared else ("NOT_EVALUATED" if review else "PASS"),
                      has_finding=bool(undeclared), status="ok", declared=sorted(store["declared"]),
                      undeclared=undeclared, review=review)
        return jsonify(result), 200

    @app.route('/androguard/lab_042', methods=['GET'])
    def detect_lab_042():
        """
        Unified packer / framework identification.
        (取代舊的 Bangcle / iJiami 獨立端點, 其特徵已併入本端點)

        加殼 = 靜態分析看不到 App 的程式碼, 其他檢測項結果不可靠 (由 lab_042 統一判斷)。
        判定為加殼 (任一成立):
          1. Manifest 的 application / appComponentFactory 是已知殼的入口 class
          2. App 自己的 Manifest 元件過半不在 dex 裡 (未知殼也抓得到)
        只命中已知殼的 .so / class 前綴, 但元件都在 dex 裡 -> 不算加殼, 也不列出
        (常是同廠商的 SDK, 如網易易盾驗證碼 Lcom/netease/nis/, 程式碼仍可分析)

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

        # 殼接管 App 啟動時的入口 class (application / appComponentFactory), 比對 class 名稱前綴
        PACKER_ENTRY_PREFIXES = [
            ("com.secapk.wrapper.",      "Bangcle"),
            ("com.secneo.apkwrapper.",   "Bangcle v2 (SecNeo)"),
            ("com.shell.",               "iJiami"),
            ("com.tencent.StubShell.",   "Tencent"),
            ("com.stub.StubApp",         "Qihoo 360"),
            ("com.qihoo.util.",          "Qihoo 360"),
            ("com.baidu.protect.",       "Baidu"),
            ("com.ali.mobisecenhance.",  "Alibaba"),
            ("com.netease.nis.wrapper.", "NetEase Yidun"),
            ("com.AppGuard.",            "AppGuard"),
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

        # ---- 加殼判定 ----
        entry_points = []
        for attr in ("name", "appComponentFactory"):
            value = a.get_attribute_value("application", attr)
            if not value:
                continue
            value = resolve_activity_name(a.get_package() or "", value)
            for prefix, name in PACKER_ENTRY_PREFIXES:
                if value.startswith(prefix):
                    entry_points.append({"attribute": attr, "class": value, "name": name})
                    break

        packing = missing_app_components(a, dx)
        packed  = bool(entry_points) or packing["suspected"]

        # 只有判定加殼才列出殼名; 入口 class 認得但特徵沒命中的也補上
        packers = list(detected_packers) if packed else []
        for ep in entry_points:
            if not any(p["name"] == ep["name"] for p in packers):
                packers.append({"name": ep["name"], "evidence": []})
            next(p for p in packers if p["name"] == ep["name"])["evidence"].append(
                "entry:" + ep["class"])

        return jsonify({
            "verdict":      "NOTICE" if packed else "PASS",
            "has_finding":  packed,
            "packed":       packed,
            "packers":      packers,             # 判定加殼時才有, 未知殼為空
            "entry_points": entry_points,
            "packing":      packing,             # App 元件不在 dex 的比例
            "signature_matches": detected_packers,  # 原始特徵命中 (未必是加殼, 不寫入報告)
            "frameworks":   detected_frameworks,
            "count":        len(packers),
            "lab_id":       "lab_042",
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

    # 4.1.5.5.1 — Root 偵測
    @app.route('/androguard/lab_056', methods=['GET'])
    def detect_lab_056():
        """
        風險: App 沒偵測 root, 攻擊者可在 root 裝置上 hook、讀取私有資料、竄改執行流程。
        檢測: App 自己的程式碼有 su 路徑 / 字串 "su"、root 管理 App 套件名稱、test-keys 等特徵字串,
              或 App 自己有呼叫 RootBeer / Play Integrity / SafetyNet / 已知 RASP SDK -> 有偵測 (只打包沒呼叫不算)。
              (File.exists() 幾乎每個 App 都有, 單獨出現不算)
        結果: 都沒有 -> WARNING (缺少防護);
              有偵測 -> NOT_EVALUATED: MAS 4.1.5.5.1 還要求偵測到後警告或關閉 App、限制非約定轉帳, 靜態無法確認, 所以不會 PASS;
              只有字串 "su" (也可能是網域、語言代碼) 或看不到 App 程式碼 (如加殼) -> NOT_EVALUATED, 列出位置。
              libsu 是用 root 執行指令的函式庫, 不是偵測 root, 不算。
        限制: 字串加密、寫在 .so、動態組字串的偵測邏輯看不到。
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
        # ro.debuggable / ro.secure 一般程式也常讀取, 只收較獨特的
        BUILD_PROPERTY_INDICATORS = ["test-keys", "ro.build.selinux"]

        def match(s):
            s = s or ""
            # 常見寫法把目錄和檔名分開 ("/system/xbin/" + "su", which su), 程式碼裡只會有 "su"; 太短, 要完全相同才算
            if s.strip() == "su":
                return "su"
            return next((k for k in ROOT_BINARY_PATHS + ROOT_MANAGEMENT_PACKAGES + BUILD_PROPERTY_INDICATORS
                         if k in s), None)

        keep = app_class_filter(a)
        strings = [e for e in find_app_const_strings(dx, match, keep)
                   if not e["class"].startswith("Lcom/topjohnwu/superuser/")]
        code_evidence = [e for e in strings if e["indicator"] != "su"]
        review = [e for e in strings if e["indicator"] == "su"]
        api_evidence = find_app_sdk_calls(dx, keep, [
            ("Lcom/scottyab/rootbeer/",    "RootBeer Library"),
            ("Lcom/scottyab/rootchecker/", "RootChecker Library"),
        ] + PLAY_INTEGRITY_PREFIXES + RASP_SDK_PREFIXES)
        if code_evidence or api_evidence:
            reason = "detection_found"
            found = {}   # 同一個 method 檢查多個特徵, 合併成一筆
            for where, note in ([("%s.%s" % (e["class"], e["method"]), e["indicator"]) for e in code_evidence]
                                + [(e["caller"], e["library"]) for e in api_evidence]):
                found.setdefault(where, []).append(note)
            review = [{"where": w, "note": ", ".join(sorted(set(notes)))} for w, notes in found.items()]
        else:
            reason = "code_not_visible" if app_code_hidden(a, dx) else ("su_string_only" if review else None)
            review = [{"where": "%s.%s" % (e["class"], e["method"]), "note": e["indicator"]} for e in review]
        return protection_result("lab_056", "Root detection implementation check",
                                 code_evidence, api_evidence, keep, reason=reason, review=review,
                                 verdict="NOT_EVALUATED" if reason else "WARNING")

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

    # 安裝來源檢查
    @app.route('/androguard/lab_064', methods=['GET'])
    def detect_lab_064():
        """
        風險: App 沒檢查安裝來源, 被重新打包後從非官方管道散布仍可正常執行。
        檢測: App 自己的程式碼呼叫 getInstallerPackageName / getInstallSourceInfo,
              或 App 自己有呼叫 Play Integrity / Google Play Licensing (LVL) / 已知 RASP SDK -> 視為有做 (只打包沒呼叫不算)。
        結果: 都沒有 -> WARNING (缺少防護)。
        限制: 反射呼叫、寫在 .so 或只在伺服器端驗證者看不到。
        """
        keep = app_class_filter(a)
        code_evidence = strip_instructions(find_app_references(dx, keep, [
            "Landroid/content/pm/PackageManager;->getInstallerPackageName",
            "Landroid/content/pm/PackageManager;->getInstallSourceInfo",
        ]))
        api_evidence = find_app_sdk_calls(dx, keep, PLAY_INTEGRITY_PREFIXES + [
            ("Lcom/google/android/vending/licensing/", "Google Play Licensing (LVL)"),
        ] + RASP_SDK_PREFIXES)
        return protection_result("lab_064", "App installation source check implementation",
                                 code_evidence, api_evidence, keep)

    #4.1.2.3.12
    @app.route('/androguard/lab_076', methods=['GET'])
    def detect_lab_076():
        """
        LAB_076: Deep Link Security (manifest-only check).
        Enumerate <activity> / <activity-alias> with action.VIEW + category.BROWSABLE + <data scheme=...>
        (skip exported="false": other apps / browsers cannot open it; enabled="false" is still checked,
         the app may enable the component at runtime)
        Public schemes shared by many apps (mailto, tel, sms, geo, file, content, market ...) are not
        the app's own links, so they are not flagged as hijack risks.
        and flag three risks:
          HIGH   - scheme="http"                                  (MITM)
          MEDIUM - http/https without android:autoVerify="true"   (host hijack)
          MEDIUM - any non-http(s) custom scheme (host does NOT help) (scheme hijack)
        """
        NS  = '{http://schemas.android.com/apk/res/android}'
        VIEW      = 'android.intent.action.VIEW'
        BROWSABLE = 'android.intent.category.BROWSABLE'
        # 系統 / 共用的 scheme: 由使用者選擇處理的 App, 不是本 App 專屬連結, 不算被劫持
        PUBLIC_SCHEMES = {'mailto', 'tel', 'sms', 'smsto', 'mms', 'mmsto', 'geo', 'file', 'content', 'market'}

        try:
            arsc = a.get_android_resources()
        except Exception:
            arsc = None

        def resolve(value):
            # scheme / host 寫成 @string/xxx 時轉成實際字串
            if value.startswith('@') and arsc is not None:
                try:
                    return arsc.get_resolved_res_configs(int(value[1:], 16))[0][1] or value
                except Exception:
                    return value
            return value

        entries = []  # one record per deep link <intent-filter>; risks list inside
        try:
            manifest_xml = a.get_android_manifest_xml()

            acts = list(manifest_xml.iter('activity')) + list(manifest_xml.iter('activity-alias'))
            for act in acts:
                name = act.get(NS + 'name', '')
                if not name:
                    continue
                # 不對外開放: 其他 App / 瀏覽器開不了, 不算 Deep Link 入口 (停用的元件可能執行時才啟用, 仍要檢查)
                if act.get(NS + 'exported', '').lower() == 'false':
                    continue

                for f in act.findall('intent-filter'):
                    if not any(x.get(NS + 'name') == VIEW      for x in f.findall('action')):
                        continue
                    if not any(x.get(NS + 'name') == BROWSABLE for x in f.findall('category')):
                        continue

                    auto_verify = f.get(NS + 'autoVerify', '').lower() == 'true'

                    for d in f.findall('data'):
                        scheme = resolve(d.get(NS + 'scheme', ''))
                        if not scheme:
                            continue
                        host = resolve(d.get(NS + 'host', ''))
                        sl   = scheme.lower()
                        if sl in PUBLIC_SCHEMES:
                            continue

                        risks = []
                        if sl == 'http':
                            risks.append(('HIGH',   'http scheme: MITM risk; use https'))
                        if sl in ('http', 'https') and not auto_verify:
                            risks.append(('MEDIUM', 'http(s) without android:autoVerify=\"true\": host hijack risk'))
                        if sl not in ('http', 'https'):
                            risks.append(('MEDIUM', 'custom scheme cannot be domain-verified (App Links), inherently hijackable regardless of host; migrate sensitive flows to https + autoVerify'))

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

    # 4.1.5.5.7 — 模擬器偵測
    @app.route('/androguard/lab_082', methods=['GET'])
    def detect_lab_082():
        """
        風險: App 沒偵測模擬器, 攻擊者可用模擬器大量自動化操作或分析 App。
        檢測: App 自己的程式碼有模擬器特徵字串 (MASTG-KNOW-0031 與常見判斷依據),
              或 App 自己有呼叫 Play Integrity / SafetyNet / 已知 RASP SDK -> 視為有做 (只打包沒呼叫不算)。
        結果: 都沒有 -> WARNING (缺少防護)。
        限制: 字串加密、寫在 .so、動態載入的偵測邏輯看不到。
        """
        # 夠獨特, 包含即算
        DISTINCT = [
            "goldfish", "ranchu", "google_sdk", "sdk_gphone", "android sdk built for",
            "genymotion", "vbox86", "bluestacks", "droid4x", "tiantianvm", "itoolsavm",
            "qemu_pipe", "qemud", "ro.kernel.qemu", "15555215554",
            "com.bignox", "com.microvirt",
            # 其他常見判斷依據: 模擬器預設 IP / 空 IMEI / 測試簽章 / CPU 資訊
            "10.0.2.15", "000000000000000", "test-keys", "/proc/cpuinfo", "ro.product.cpu.abi",
        ]
        # 太常見, 要整個字串完全相同才算
        EXACT = {"generic", "sdk", "emulator", "nox", "andy", "ttvm"}

        def match(s):
            s = (s or "").strip().lower()
            if s in EXACT:
                return s
            return next((k for k in DISTINCT if k in s), None)

        keep = app_class_filter(a)
        code_evidence = find_app_const_strings(dx, match, keep)
        api_evidence = find_app_sdk_calls(dx, keep, PLAY_INTEGRITY_PREFIXES + RASP_SDK_PREFIXES)

        implemented = bool(code_evidence or api_evidence)
        return jsonify({
            "verdict":       "PASS" if implemented else "WARNING",
            "has_finding":   not implemented,   # True = 缺少防護
            "implemented":   implemented,
            "code_evidence": code_evidence,
            "api_evidence":  api_evidence,
            "scanned_app_classes": count_app_classes(dx, keep),
            "count":         len(code_evidence) + len(api_evidence),
            "lab_id":        "lab_082",
            "description":   "Emulator detection implementation check",
        }), 200

    # 4.1.5.5.8 — USB 偵錯偵測
    @app.route('/androguard/lab_083', methods=['GET'])
    def detect_lab_083():
        """
        風險: App 沒偵測 USB / 無線偵錯, 攻擊者或木馬可透過 ADB 操控裝置與 App。
        檢測: App 自己的程式碼讀取 adb_enabled / adb_wifi_enabled /
              development_settings_enabled 或 adb 服務屬性, 或 App 自己有呼叫已知 RASP SDK -> 視為有做 (只打包沒呼叫不算)。
              Play Integrity 不判斷偵錯狀態, 不算。
        結果: 都沒有 -> WARNING (缺少防護)。
        限制: 字串加密、寫在 .so、動態組字串的偵測邏輯看不到。
        """
        # Settings.Global 常數編譯後會變成字串
        SETTINGS_KEYS = {"adb_enabled", "adb_wifi_enabled", "development_settings_enabled"}
        # 直接查 adb 服務狀態的系統屬性
        ADB_PROPS = {"init.svc.adbd", "service.adb.tcp.port"}

        def match(s):
            s = (s or "").strip()
            return s if s in SETTINGS_KEYS or s in ADB_PROPS else None

        keep = app_class_filter(a)
        code_evidence = find_app_const_strings(dx, match, keep)
        api_evidence = find_app_sdk_calls(dx, keep, RASP_SDK_PREFIXES)

        implemented = bool(code_evidence or api_evidence)
        return jsonify({
            "verdict":       "PASS" if implemented else "WARNING",
            "has_finding":   not implemented,   # True = 缺少防護
            "implemented":   implemented,
            "code_evidence": code_evidence,
            "api_evidence":  api_evidence,
            "scanned_app_classes": count_app_classes(dx, keep),
            "count":         len(code_evidence) + len(api_evidence),
            "lab_id":        "lab_083",
            "description":   "USB debugging detection implementation check",
        }), 200

    # 4.1.5.5.6 — 程式碼混淆
    @app.route('/androguard/lab_084', methods=['GET'])
    def detect_lab_084():
        """
        風險: 程式碼沒混淆, 反編譯就看得懂邏輯, 容易找到防護位置並竄改。
        檢測: 只看 App 自己的套件 (Manifest package、啟動 Activity), 排除編譯器產生與必須保留原名的部分,
              統計 class / method / field 短名稱 (a、b、aa) 比例。
              自己的套件幾乎沒有 class 時, 改看是否被搬到 o、a.b 這類短套件 (DexGuard / R8 repackageclasses)。
        結果: 任一比例達門檻, 或自己的套件被搬空且短套件 class 達 OBF_REPACKAGED_MIN 個 -> PASS;
              看得到的 class 太少又沒有搬移 (如加殼) -> NOT_EVALUATED (報告顯示 Not evaluated); 其他 -> WARNING。
        限制: 只看名稱混淆, 字串加密、控制流程混淆不判斷; 基準(2) 反混淆需人工。
        """
        stats = obfuscation_stats(a, dx)
        if stats["scanned_app_classes"] < OBF_MIN_CLASSES:
            # 自己的套件看不到程式碼: 被搬到短套件 -> 有混淆; 都沒有 -> 多半是加殼, 無法判定
            verdict = "PASS" if stats["repackaged_classes"] >= OBF_REPACKAGED_MIN else "NOT_EVALUATED"
        elif max(stats["class_ratio"], stats["method_ratio"], stats["field_ratio"]) >= OBF_RATIO_THRESHOLD:
            verdict = "PASS"
        else:
            verdict = "WARNING"
        return jsonify(dict(stats,
            verdict=verdict,
            has_finding=verdict == "WARNING",   # True = 沒有混淆
            threshold=OBF_RATIO_THRESHOLD,
            min_classes=OBF_MIN_CLASSES,
            repackaged_min=OBF_REPACKAGED_MIN,
            lab_id="lab_084",
            description="Code obfuscation check (short identifier ratio in the app's own packages)",
        )), 200

    # 4.1.3.1.1 — 交易資源使用聲明
    @app.route('/androguard/lab_085', methods=['GET'])
    def detect_lab_085():
        """
        風險: 交易前沒告知商品、金額、付款方式, 使用者可能在不知情下付款。
        檢測: 找交易管道 (見 find_payment_channels): Google Play 內購由平台畫面顯示商品 / 金額 / 付款方式 -> 沒問題;
              Google Pay 檢查 App 自己組的請求有沒有 MAS 要求的商品名稱 (displayItems)、金額 (totalPrice)、交易方式 (allowedPaymentMethods);
              Samsung Pay 同樣檢查 App 組的付款畫面 (CustomSheet) 有沒有金額 (AmountBoxControl)、商品明細 (addItem);
              其他商店內購 (華為、Samsung、Amazon) 同 Play 內購; 第三方支付 SDK、網頁金流網址、電子支付 App (街口等)、
              信用卡 CVV 欄位、交易專用介面文字 (含點數兌換、儲值、購票、證券下單)、NFC 感應支付、自建交易畫面、找不到交易畫面的金融 App
              -> 畫面內容看不到; NFC 付款服務要求解鎖 (requireDeviceUnlock) -> 現場授權, 符合; 有內購時其他管道也照樣檢查。
        結果: Google Pay 請求缺金額或交易方式 -> WARNING; 只缺商品名稱 (可能已顯示在 App 結帳頁) 與其他看不到的管道 -> NOT_EVALUATED;
              只有 Play 內購或沒有交易 -> PASS。
        限制: 只看請求欄位有沒有出現, 不看值; 只認清單內的 SDK 與名稱關鍵字;
              僅收款 (不適用) 與外匯、期貨、虛擬貨幣的例外需人工判斷。
        """
        keep = app_class_filter(a)
        channels = find_payment_channels(a, dx, keep)
        findings = [c for c in channels if c["problem"] and c["confidence"] == "high"]
        review = [c for c in channels if c["problem"] and c not in findings]
        return jsonify({
            "verdict":     "WARNING" if findings else ("NOT_EVALUATED" if review else "PASS"),
            "has_finding": bool(findings),
            "channels":    channels,
            "findings":    findings,
            "review":      review,
            "count":       len(findings),
            "lab_id":      "lab_085",
            "description": "Transaction notice check (payment requests without product name or amount)",
        }), 200

    # 4.1.2.3.1 — 敏感性資料儲存聲明
    @app.route('/androguard/lab_086', methods=['GET'])
    def detect_lab_086():
        """
        風險: App 把敏感資料存在裝置上, 沒先告知並取得同意。
        檢測: 找敏感資料寫進 SharedPreferences / DataStore / SQLite / 檔案 (見 find_sensitive_storage),
              有的話再找同意機制 (見 find_storage_consent): 讀寫同意狀態、同意畫面、同意管理 SDK -> 有取得同意;
              只有隱私權政策連結 / 文字、條款畫面 -> 只有告知。
              有同意機制時再看 Google Play 資料安全性頁面有沒有列出每一類儲存的資料 (商店聲明), 列給人工確認。
        結果: 確定有儲存敏感資料且完全沒有同意或告知 -> WARNING;
              有同意機制 (靜態確認不了同意在儲存之前、涵蓋所有資料)、只有告知、只有待確認的儲存、程式碼看不到
              -> NOT_EVALUATED; 沒有儲存敏感資料 -> PASS。
        限制: 不看聲明內容; 商店說明文字、未上架 App 的調查表需人工確認。
        """
        r = storage_consent_result(a, dx)
        verdict = r["verdict_086"]
        return jsonify({
            "verdict":     verdict,
            "has_finding": verdict == "WARNING",
            "reason":      r["reason"],
            "storage":     storage_items(r["storage"]),
            # 無法判定時連同確定的儲存一起列出, 供人工確認
            "review":      storage_items(r["review"] + (r["storage"] if verdict == "NOT_EVALUATED" else [])),
            "consent":     r["consent"],
            "own_classes": r["own_classes"],
            "count":       len(r["storage"]) if verdict == "WARNING" else 0,
            "lab_id":      "lab_086",
            "description": "Sensitive data storage notice check (stored without consent or notice)",
        }), 200

    # 4.1.2.3.2 — 拒絕敏感性資料儲存
    @app.route('/androguard/lab_087', methods=['GET'])
    def detect_lab_087():
        """
        風險: 使用者無法拒絕 App 儲存敏感資料。
        檢測: 同 lab_086 的敏感資料儲存, 從寫入的 method 往上追 4 層呼叫: 有沒有讀「記住帳號 / 儲存密碼」這類開關
              (SharedPreferences、DataStore、勾選框 isChecked), 且讀到的值拿來決定要不要儲存。
              lab_086 不符合 (沒聲明) 時此項也不符合 (標準規定)。
        結果: lab_086 WARNING, 或確定的儲存在路徑上完全沒讀設定 / 開關讀了沒拿來判斷 -> WARNING;
              開關值傳到別處、開關 key 看不出來、只有名稱認不出的設定拿來判斷、對話框按鈕後才儲存、
              找不到寫入位置 (Room、DataStore key)、待確認的儲存、lab_086 NOT_EVALUATED -> NOT_EVALUATED (有開關的儲存也列出); 其他 -> PASS。
        限制: 開關只認 key 名稱 (remember、save 等); 不確認拒絕後真的沒存 (基準(2) 需動態)。
        """
        r = storage_consent_result(a, dx)
        items = []
        if r["verdict_086"] != "WARNING":
            cache = {"methods": {}, "getters": {}}
            try:
                arsc = a.get_android_resources()
            except Exception:
                arsc = None
            cache["getters"]["_arsc"] = arsc

            def kind_of(key):
                if isinstance(key, int) and not isinstance(key, bool):
                    key = resource_name(arsc, key)
                # 混淆後的欄位名 (H、aB) 看不出用途
                if not isinstance(key, str) or len(key) <= 2:
                    return ("unknown", None)
                return ("share", key) if STORE_SWITCH_RE.search(split_words(key)) else ("other", key)

            for s in r["storage"]:
                item = {k: v for k, v in s.items() if k != "method"}
                if s["method"] is None:
                    item.update(problem="storing code not located (e.g. Room table, DataStore key)", unverified=True)
                else:
                    ev = path_evidence(dx, [s["method"]], cache, kind_of, reader=store_switch_reads)
                    item["evidence"] = {k: ev[k] for k in ("keys", "other_keys", "gating", "default_on", "dialog")}
                    item["problem"] = None
                    if not ev["switch"] and ev["switch_unverified"]:
                        item.update(problem="a setting is read on the path but its key cannot be identified", unverified=True)
                    elif not ev["switch"] and ev.get("other_used"):
                        item.update(problem="settings with unrecognized names decide on the path; one may be the refusal option",
                                    unverified=True)
                    elif not ev["switch"] and ev["dialog"]:
                        # 對話框按下確認才儲存 (例「信任此裝置?」): 使用者可能可以按取消拒絕, 看不到按鈕內容
                        item.update(problem="stored after a dialog button; the dialog may let users refuse", unverified=True)
                    elif not ev["switch"]:
                        item["problem"] = "no option to refuse storing"
                    elif ev["gating"] == "none":
                        item["problem"] = "option is read but not used to decide"
                    elif ev["gating"] == "unknown":
                        item.update(problem="option value is used elsewhere, effect not verified", unverified=True)
                items.append(item)
        findings = [i for i in items if i["problem"] and not i.get("unverified")]
        review = [i for i in items if i["problem"] and i.get("unverified")] \
            + [dict(s, problem=s["reason"]) for s in storage_items(r["review"])]
        if r["verdict_086"] == "WARNING":
            verdict, reason = "WARNING", "4.1.2.3.1 not met: " + r["reason"]
            findings = [dict(s, problem="stored without notice, so users cannot refuse it")
                        for s in storage_items(r["storage"])]
        elif findings:
            verdict, reason = "WARNING", "sensitive data stored without an option to refuse"
        elif review or r["verdict_086"] == "NOT_EVALUATED":
            verdict, reason = "NOT_EVALUATED", r["reason"] if not review else "refusal option could not be verified"
            # AS-lab086 無法判定 (聲明不確定): 有開關的儲存也列出來, 給人工確認
            review += [dict(i, problem="controlled by a user option, but the AS-lab086 declaration could not be confirmed")
                       for i in items if not i["problem"]]
        else:
            verdict, reason = "PASS", r["reason"] if not items else "every storage is controlled by a user option"
        return jsonify({
            "verdict":     verdict,
            "has_finding": verdict == "WARNING",
            "reason":      reason,
            "storage":     items,
            "findings":    findings,
            "review":      review,
            "own_classes": r["own_classes"],
            "count":       len(findings),
            "lab_id":      "lab_087",
            "description": "Sensitive data storage refusal check (no user option to refuse storing)",
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

    # ========================================================================
    # 共用函式 / 常數 — 放在所有 lab 端點之後
    # 新增共用函式請放在這一區對應的分類, 並在說明寫上「使用: lab_xxx」;
    # 新增或移除使用的 lab 時, 記得同步更新「使用」清單。
    # 端點是收到請求時才呼叫這些函式, 所以定義在端點後面不影響執行。
    # ========================================================================

    # ---- 程式碼掃描 ----

    def iter_app_methods(dx):
        """逐一取出 App 的 method (略過 FilteringEngine 排除的系統 / 函式庫 class), 回傳 (class 名, method, method_analysis)
        使用: lab02, lab_001, lab_022, lab_28, lab_034, lab036, lab_044, lab_055, lab_057, lab_058, lab_060, lab_063, lab_065, lab_070, lab_071, lab_073, lab_074, lab_075, lab_077, lab_078, lab_079, lab_080"""
        for class_name, cls_value in dx.classes.items():
            if not FilteringEngine.is_class_name_not_in_exclusion(class_name):
                continue
            for method in cls_value.get_methods():
                m = method.get_method()
                if m:
                    yield class_name, method, m

    def find_method_calls(dx, target_class=None, target_method=None):
        """找出呼叫 target_class / target_method 的指令位置 (含函式庫, 不排除), 回傳每個呼叫的 method 與指令索引
        使用: lab031, lab035, lab038"""
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

    def resolve_activity_name(package_name, activity_name):
        """把 Manifest 的簡寫元件名補成完整 class 名: '.MyActivity' / 'MyActivity' -> 'com.example.app.MyActivity', 已是完整名稱則不變
        使用: lab036, lab_039, lab_042, lab_077, lab_084, lab_085, lab_086 (透過 find_storage_consent)"""
        if activity_name.startswith('.'):
            return package_name + activity_name
        elif '.' not in activity_name:
            return package_name + '.' + activity_name
        return activity_name

    # ---- App 自己的程式碼範圍 ----

    # FilteringEngine 排除清單之外, 再排除的常見第三方 SDK / 執行環境 (給 app_class_filter 用)
    # 使用: lab_026, lab_027, lab_042, lab_056, lab_064, lab_082, lab_083, lab_085 (透過 app_class_filter)
    EXTRA_LIB_PREFIXES = (
        "Ljava/", "Ljavax/", "Lcom/facebook/", "Lio/flutter/", "Lio/reactivex/",
        "Lcom/squareup/", "Lokhttp3/", "Lokio/", "Lretrofit2/", "Lcom/bumptech/",
        "Lcom/airbnb/", "Lcom/unity3d/", "Lcom/tencent/", "Lcom/alibaba/",
        "Lcom/huawei/", "Lcom/amazonaws/", "Lcom/appsflyer/", "Lcom/adjust/",
        "Lcom/onesignal/", "Lcom/microsoft/", "Lcom/crashlytics/", "Lio/sentry/",
    )

    def app_class_filter(a):
        """回傳 keep(class 名) 判斷函式: 是否為 App 自己的程式碼 (App 套件優先, 再排除 FilteringEngine 與 EXTRA_LIB_PREFIXES)
        使用: lab_026, lab_027, lab_039, lab_040, lab_041, lab_056, lab_064, lab_082, lab_083, lab_085, lab_086, lab_087; 透過 missing_app_components 也給 lab_042 用"""
        pkg = (a.get_package() or "").replace(".", "/")
        own = ("L" + pkg + "/") if pkg else None

        def keep(class_name):
            # App 自己的套件優先: 即使前綴在排除清單 (如 org.*) 也要掃
            if own and class_name.startswith(own):
                return True
            if not FilteringEngine.is_class_name_not_in_exclusion(class_name):
                return False
            return not class_name.startswith(EXTRA_LIB_PREFIXES)

        return keep

    def count_app_classes(dx, keep):
        """計算 keep 範圍內的 class 數 (回傳結果的 scanned_app_classes, 看掃描範圍是否合理)
        使用: lab_082, lab_083; 透過 protection_result 也給 lab_026, lab_027, lab_056, lab_064 用, 透過 share_check_result 也給 lab_039, lab_040 用"""
        return sum(1 for c in dx.classes if keep(c))

    # ---- 防護證據搜尋 ----

    def find_app_const_strings(dx, match, keep):
        """掃 App 自己程式碼的 const-string, match(字串) 回傳命中的特徵或 None; 適合證據是字串的檢測 (su 路徑、套件名)
        使用: lab_041, lab_056, lab_082, lab_083, lab_085"""
        found, seen = [], set()
        for class_name, cls_value in dx.classes.items():
            if not keep(class_name):
                continue
            for method in cls_value.get_methods():
                method_analysis = method.get_method()
                if not method_analysis:
                    continue
                try:
                    instructions = list(method_analysis.get_instructions())
                except Exception:
                    continue
                for ins in instructions:
                    try:
                        if ins.get_op_value() not in (0x1A, 0x1B):
                            continue
                        hit = match(ins.get_string())
                    except Exception:
                        continue
                    key = (class_name, method.name, hit)
                    if hit and key not in seen:
                        seen.add(key)
                        found.append({"class": class_name, "method": method.name, "indicator": hit})
        return found

    def find_app_references(dx, keep, targets):
        """掃 App 自己程式碼的指令, 找引用到 targets 的 API 呼叫 / 欄位存取 (substring 比對); 適合證據是 API 的檢測
        使用: lab_026, lab_027, lab_041, lab_064, lab_085"""
        found = []
        for class_name, cls_value in dx.classes.items():
            if not keep(class_name):
                continue
            for method in cls_value.get_methods():
                method_analysis = method.get_method()
                if not method_analysis:
                    continue
                try:
                    instructions = list(method_analysis.get_instructions())
                except Exception:
                    continue
                for i, ins in enumerate(instructions):
                    try:
                        out = ins.get_output()
                    except Exception:
                        continue
                    hit = next((t for t in targets if t in out), None)
                    if hit:
                        found.append({"class": class_name, "method": method.name, "api": hit,
                                      "instructions": instructions, "index": i})
        return found

    def strip_instructions(refs):
        """拿掉 find_app_references 結果中的 instructions (無法轉 JSON), 只留 class / method / api
        使用: lab_026, lab_027, lab_041, lab_064, lab_085"""
        return [{"class": r["class"], "method": r["method"], "api": r["api"]} for r in refs]

    def find_class_prefixes(dx, prefixes):
        """回傳 APK 內出現過的 class 前綴 (含函式庫), 用來判斷有沒有引入某個 SDK
        使用: lab_041, lab_085"""
        found = []
        for prefix, name in prefixes:
            for class_name in dx.classes:
                if class_name.startswith(prefix):
                    found.append({"class": class_name, "library": name})
                    break
        return found

    def find_app_sdk_calls(dx, keep, prefixes):
        """App 自己的程式碼有呼叫某個 SDK 的 method (含建構子) 才算有用; 只打包或被其他函式庫帶進來的不算
        回傳 [{"class": SDK class, "library", "caller": 呼叫的位置}], 每個 SDK 只列第一筆
        使用: lab_026, lab_056, lab_064, lab_082, lab_083, lab_086 (透過 find_storage_consent)"""
        found = []
        for prefix, name in prefixes:
            hit = None
            for class_name, ca in dx.classes.items():
                if not class_name.startswith(prefix):
                    continue
                for ma in ca.get_methods():
                    try:
                        callers = [m for _, m, _ in ma.get_xref_from()]
                    except Exception:
                        continue
                    caller = next((m for m in callers if keep(m.class_name)), None)
                    if caller is not None:
                        hit = {"class": class_name, "library": name,
                               "caller": "%s.%s" % (caller.class_name[1:-1].replace("/", "."), caller.name)}
                        break
                if hit:
                    break
            if hit:
                found.append(hit)
        return found

    # 已知 RASP 防護 SDK 的 class 前綴; App 自己有呼叫才算有做對應的偵測 (見 find_app_sdk_calls)
    # 使用: lab_026, lab_056, lab_064, lab_082, lab_083
    RASP_SDK_PREFIXES = [
        ("Lcom/aheaditec/talsec_security/", "freeRASP (Talsec)"),
        ("Lapp/talsec/rasp/",               "freeRASP (Talsec)"),
    ]

    # Google Play Integrity / SafetyNet 的 class 前綴; App 自己有呼叫才算有做完整性 / 環境檢查
    # 使用: lab_026, lab_056, lab_064, lab_082
    PLAY_INTEGRITY_PREFIXES = [
        ("Lcom/google/android/play/core/integrity/", "Google Play Integrity API"),
        ("Lcom/google/android/gms/safetynet/",       "Google SafetyNet API"),
    ]

    # ---- 分享管道與商店聲明 ----

    ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

    # androidx 設定頁 XML 常用 app:key
    # 使用: lab_040 (透過 settings_switch_keys)
    APP_NS = "{http://schemas.android.com/apk/res-auto}"

    # provider 會回傳資料的 method
    # 使用: lab_039, lab_040 (透過 find_auto_share_channels)
    PROVIDER_DATA_METHODS = {"query", "openFile", "openAssetFile", "openTypedAssetFile", "call"}

    # 送出廣播 / 啟動其他元件的 API (第一個參數是 Intent)
    # 使用: lab_039, lab_040 (透過 find_intent_channels)
    BROADCAST_APIS = {"sendBroadcast", "sendOrderedBroadcast", "sendStickyBroadcast",
                      "sendBroadcastAsUser", "sendOrderedBroadcastAsUser", "sendStickyBroadcastAsUser"}
    # 開啟畫面 (使用者看得到, 由使用者操作觸發), 不算自動分享
    ACTIVITY_LAUNCH_APIS = {"startActivity", "startActivityForResult", "startActivities", "startActivityIfNeeded"}
    # 背景啟動其他 App 的元件, 使用者看不到
    SERVICE_LAUNCH_APIS = {"startService", "startForegroundService", "bindService"}

    # 使用者自己觸發的 intent action (分享選單、拍照、用其他 App 開啟), 對象由使用者選, 不算自動分享
    # 使用: lab_039, lab_040 (透過 find_intent_channels)
    USER_INITIATED_ACTIONS = ("android.intent.action.SEND", "android.intent.action.SEND_MULTIPLE",
                              "android.intent.action.SENDTO", "android.intent.action.VIEW",
                              "android.intent.action.EDIT", "android.intent.action.CHOOSER",
                              "android.media.action.IMAGE_CAPTURE", "android.media.action.VIDEO_CAPTURE")

    # 送給系統的固定廣播, 內容不是使用者的敏感資料 (媒體掃描、桌面捷徑、音效等化器)
    # 使用: lab_039, lab_040 (透過 find_intent_channels)
    SYSTEM_BROADCAST_ACTIONS = ("android.intent.action.MEDIA_SCANNER_SCAN_FILE",
                                "com.android.launcher.action.INSTALL_SHORTCUT",
                                "com.android.launcher.action.UNINSTALL_SHORTCUT",
                                "android.media.action.OPEN_AUDIO_EFFECT_CONTROL_SESSION",
                                "android.media.action.CLOSE_AUDIO_EFFECT_CONTROL_SESSION")

    # 只送桌面圖示角標數字給桌面程式的函式庫, 不是分享資料 (字串常被加密, 看不出 action)
    # 使用: lab_039, lab_040 (透過 find_intent_channels)
    BADGE_LIB_PREFIXES = ("Lme/leolin/shortcutbadger/",)

    # 敏感資料關鍵字 (比對 extra key、欄位名等字串; 駝峰會先拆成底線, 前面不能接英文字母)
    # 使用: lab_039, lab_040 (透過 sensitive_keyword)
    SENSITIVE_KEYWORD_RE = re.compile(
        r"(?<![a-z])(password|passwd|passcode|token|secret|credential|cookie|session_id|"
        r"contact|location|latitude|longitude|phone|imei|imsi|iccid|msisdn|e_?mail|birthday|"
        r"id_?card|national_id|card_?number|card_?no|credit_card|cvv|ssn|sms|account)"
        r"|密碼|帳號|身分證|電話|手機|信用卡|生日|通訊錄|定位")

    # 分享開關的 key 關鍵字; 其他用途的 boolean 設定 (例 自動播放、時區) 不算分享開關
    # 使用: lab_039, lab_040 (透過 switch_kind)
    SHARE_SWITCH_RE = re.compile(
        r"(?<![a-z])(share|sharing|consent|agree|privacy|analytics?|tracking|telemetry|crash|report|"
        r"usage|collect|collection|opt_?in|opt_?out|gdpr|personali[sz]ed|ads?|third_?party|"
        r"content_?provider)(?![a-z])|同意|分享|隱私")

    # provider 內檢查呼叫者身分的 API (配合簽章 / 權限比對, 只讓特定 App 讀取)
    # 使用: lab_039, lab_040 (透過 provider_caller_check)
    CALLER_ID_APIS = ("->getCallingPackage(", "->getCallingPackageUnchecked(", "Landroid/os/Binder;->getCallingUid(")
    CALLER_VERIFY_APIS = ("->checkSignatures(", "->hasSigningCertificate(", "Landroid/content/pm/PackageInfo;->signatures",
                          "Landroid/content/pm/PackageInfo;->signingInfo", "->enforceCallingPermission(",
                          "->checkCallingPermission(", "->enforceCallingOrSelfPermission(", "->checkCallingOrSelfPermission(")

    # 設定頁的開關元件 (只比對類別名稱結尾)
    # 使用: lab_040 (透過 settings_switch_keys)
    SETTINGS_SWITCH_TAGS = ("SwitchPreference", "SwitchPreferenceCompat", "CheckBoxPreference", "TwoStatePreference")

    def split_words(value):
        """駝峰拆成底線並轉小寫, 例 'authToken' -> 'auth_token'
        使用: lab_039, lab_040 (透過 sensitive_keyword, switch_kind), lab_086, lab_087"""
        return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value or "").lower()

    def sensitive_keyword(value):
        """字串含敏感資料關鍵字 -> 回傳該關鍵字, 否則 None
        使用: lab_039, lab_040"""
        m = SENSITIVE_KEYWORD_RE.search(split_words(value)) if isinstance(value, str) else None
        return m.group(0) if m else None

    def sensitive_api_names():
        """敏感資料 API -> 名稱 (沿用 lab_041 的 DATA_SAFETY_MAP, 不看權限)
        使用: lab_039, lab_040 (透過 method_sensitive_evidence), lab_086, lab_087 (透過 find_sensitive_storage)"""
        return [(api, e["name"]) for e in DATA_SAFETY_MAP for api in e.get("apis", [])]

    def method_sensitive_evidence(ma, api_names, strings=True):
        """一個 method 的指令有讀敏感資料的 API (strings=True 時含敏感關鍵字的字串也算) -> 回傳說明, 否則 None
        使用: lab_039, lab_040"""
        try:
            instructions = [] if ma.is_external() else list(ma.get_method().get_instructions())
        except Exception:
            return None
        for ins in instructions:
            out = ins.get_output()
            hit = next((name for api, name in api_names if api in out), None)
            if hit:
                return "reads %s" % hit
            if strings and ins.get_name().startswith("const-string"):
                word = sensitive_keyword(ins.get_string())
                if word:
                    return "uses '%s'" % ins.get_string()[:60]
        return None

    def is_weak_level(level):
        """protectionLevel 是 normal / dangerous / 沒寫 -> True (其他 App 拿得到, 等於沒保護)
        androguard 解析自訂權限是 8 位數 hex (例 '0x00000002'), 系統權限是文字 (例 'normal|instant', 只看 | 前的基本等級)
        使用: lab_039, lab_040 (透過 find_auto_share_channels)"""
        level = (level or "").strip().lower()
        if not level.startswith("0x") and not level.isdigit():
            return level.split("|")[0] in ("", "normal", "dangerous")
        try:
            return (int(level, 0) & 0xF) in (0, 1)   # 0 = normal, 1 = dangerous
        except ValueError:
            return False

    def platform_permission_levels():
        """系統權限 -> protectionLevel (androguard 內建資料, API 34); 載入失敗回傳空 dict
        使用: lab_039, lab_040 (透過 find_auto_share_channels)"""
        try:
            from androguard.core.api_specific_resources import load_permissions
            return {k: v.get("protectionLevel", "") for k, v in load_permissions(34).items()}
        except Exception:
            return {}

    def ins_registers(ins):
        """指令用到的暫存器, 例 ['v0', 'v1']; invoke/range 的 'v1 ... v7' 會展開
        使用: lab_039, lab_040 (透過 find_intent_channels, switch_reads), lab_086, lab_087"""
        try:
            prefix = ins.get_output().split('L', 1)[0]
        except Exception:
            return []
        regs = re.findall(r'\bv\d+\b', prefix)
        if '/range' in ins.get_name() and len(regs) == 2 and '...' in prefix:
            return ['v%d' % r for r in range(int(regs[0][1:]), int(regs[1][1:]) + 1)]
        return regs

    def invoke_args(name, out, regs):
        """invoke 指令每個參數 (不含 this) 對應的 (型別, 暫存器); long / double 佔兩個暫存器
        使用: lab_039, lab_040 (透過 find_intent_channels, switch_reads), lab_086, lab_087"""
        m = re.search(r'\(([^)]*)\)', out)
        params = re.findall(r'\[*(?:L[^;]+;|[ZBSCIJFD])', m.group(1).replace(' ', '')) if m else []
        i = 0 if 'static' in name else 1
        args = []
        for p in params:
            args.append((p, regs[i] if i < len(regs) else None))
            i += 2 if p in ('J', 'D') else 1
        return args

    def new_intent():
        """Intent 追蹤狀態: target = None (沒指定接收者) / "self" (自己 App) / 套件名 / "unknown" (指定了但看不出是誰)
        使用: lab_039, lab_040 (透過 find_intent_channels)"""
        return {"kind": "intent", "target": None, "payload": False, "action": None, "user": False, "grant": False,
                "keys": []}

    def update_intent(intent, api, args, own):
        """依 Intent 的建構子 / setter 更新追蹤狀態 (接收者、是否帶資料、action、URI 授權旗標)
        args: [(型別, 值)]; 有 Context 參數的建構子 / setClass 一定指向自己 App
        使用: lab_039, lab_040 (透過 find_intent_channels)"""
        types = [t for t, _ in args]
        vals = [v for _, v in args]

        def package_of(value):
            return ("self" if value == own else value) if isinstance(value, str) else "unknown"

        if api == "<init>":
            if types == ["Landroid/content/Intent;"]:
                src = vals[0]
                intent.update(src if isinstance(src, dict) and src.get("kind") == "intent" else {"target": "unknown"})
            if "Landroid/content/Context;" in types:
                intent["target"] = "self"
            if types and types[0] == "Ljava/lang/String;" and isinstance(vals[0], str):
                intent["action"] = vals[0]
            if "Landroid/net/Uri;" in types:
                intent["payload"] = True
        elif api in ("setClass", "setClassName") and types and types[0] == "Landroid/content/Context;":
            intent["target"] = "self"
        elif api == "setClassName":
            intent["target"] = package_of(vals[0] if vals else None)
        elif api == "setComponent":
            comp = vals[0] if vals else None
            intent["target"] = comp.get("target") or "unknown" if isinstance(comp, dict) else "unknown"
        elif api == "setPackage":
            intent["target"] = package_of(vals[0] if vals else None)
        elif api == "setAction" and vals and isinstance(vals[0], str):
            intent["action"] = vals[0]
        elif api.startswith("put") or api in ("setData", "setDataAndType", "setDataAndNormalize",
                                               "setDataAndTypeAndNormalize", "setClipData"):
            intent["payload"] = True
            if api == "putExtra" and vals and isinstance(vals[0], str):
                intent["keys"] = intent.get("keys", []) + [vals[0]]   # extra 的 key, 用來判斷是不是敏感資料
        elif api in ("addFlags", "setFlags") and vals and isinstance(vals[0], int) and vals[0] & 3:
            intent["grant"] = True   # FLAG_GRANT_READ / WRITE_URI_PERMISSION
        intent["user"] = intent["user"] or intent["action"] in USER_INITIATED_ACTIONS

    # Context 系列的系統類別; 呼叫者是這些 (或繼承它們的 App 類別) 時, getPackageName() 回傳的是自己的套件名
    # 使用: lab_039, lab_040 (透過 is_context_class)
    CONTEXT_CLASSES = {"Landroid/content/Context;", "Landroid/content/ContextWrapper;", "Landroid/view/ContextThemeWrapper;",
                       "Landroid/app/Activity;", "Landroid/app/Application;", "Landroid/app/Service;",
                       "Landroid/app/IntentService;", "Landroid/app/job/JobService;"}

    def is_context_class(dx, name, cache):
        """name 是 Context 或繼承 Context 的類別 (往上追父類別最多 15 層)
        使用: lab_039, lab_040 (透過 find_intent_channels)"""
        if name not in cache:
            current, result = name, False
            for _ in range(15):
                if current in CONTEXT_CLASSES:
                    result = True
                    break
                ca = dx.classes.get(current)
                parent = getattr(ca, "extends", None) if ca is not None else None
                if not parent or parent == current:
                    break
                current = str(parent)
            cache[name] = result
        return cache[name]

    def find_intent_channels(a, dx, keep, levels):
        """逐一看 App 自己的 method, 追蹤同一個 method 內組出來的 Intent, 找把資料送到其他 App 的呼叫
        回傳 [{"type", "where", "target", "confidence", "reason", "sensitive", "sensitive_evidence", "method"}]
          confidence "high"   = 確定會送到其他 App: 沒指定接收者又帶資料的廣播、不是使用者觸發的 grantUriPermission
                     "review" = 可能送到其他 App, 但接收者不明或 Intent 在其他 method 組成, 需人工確認
          sensitive  True = 確定是敏感資料 (extra key 含敏感關鍵字, 或同一個 method 讀了敏感資料 API); None = 看不出來
          自己 App 內部 (Intent(context, X.class)、setPackage(getPackageName()))、LocalBroadcastManager、
          開啟畫面 (startActivity, 使用者看得到)、分享選單 / 拍照、送給系統的固定廣播 (媒體掃描等) 都不算
        使用: lab_039, lab_040 (透過 find_auto_share_channels)"""
        own = a.get_package() or ""
        found, seen = [], {}
        api_names = sensitive_api_names()
        context_cache = {}

        def add(kind, where, target, confidence, reason, ma, sensitive=None):
            # 同一個 method 有多個同類呼叫時合併成一筆, 有確定的就以確定的為準
            if sensitive is None:
                evidence = method_sensitive_evidence(ma, api_names, strings=False)
                sensitive = evidence and (True, evidence)
            sens, sens_ev = sensitive or (None, None)
            old = seen.get((kind, where))
            if old is None:
                seen[(kind, where)] = {"type": kind, "where": where, "target": target,
                                       "confidence": confidence, "reason": reason,
                                       "sensitive": sens, "sensitive_evidence": sens_ev, "method": ma}
                found.append(seen[(kind, where)])
            else:
                if confidence == "high" and old["confidence"] != "high":
                    old.update(target=target, confidence=confidence, reason=reason)
                if sens and not old["sensitive"]:
                    old.update(sensitive=sens, sensitive_evidence=sens_ev)

        for cls, ca in dx.classes.items():
            if not keep(cls) or cls.startswith(BADGE_LIB_PREFIXES):
                continue
            for ma in ca.get_methods():
                if ma.is_external():
                    continue
                try:
                    instructions = list(ma.get_method().get_instructions())
                except Exception:
                    continue
                outs = [ins.get_output() for ins in instructions]
                if not any(api in o for o in outs for api in ("Broadcast", "startActivit", "Service(", "grantUriPermission")):
                    continue
                where = "%s.%s" % (cls[1:-1].replace("/", "."), ma.name)
                # user_launch: 這個 method 真的有啟動分享選單 / 拍照等使用者操作的 Intent
                # branches: 目前經過幾個分支, 用來判斷 setPackage 等是不是只在某條路徑執行
                values, pending, grants, user_launch, branches = {}, None, [], False, 0
                for ins, out in zip(instructions, outs):
                    name = ins.get_name()
                    regs = ins_registers(ins)
                    if name.startswith("const-string") and regs:
                        values[regs[0]] = ins.get_string()
                    elif name == "const-class" and regs:
                        values[regs[0]] = None
                    elif name.startswith("const") and regs:
                        try:
                            values[regs[0]] = ins.get_literals()[0]
                        except Exception:
                            values[regs[0]] = None
                    elif name == "new-instance" and regs:
                        if out.endswith("Landroid/content/Intent;"):
                            values[regs[0]] = dict(new_intent(), born=branches)
                        elif out.endswith("Landroid/content/ComponentName;"):
                            values[regs[0]] = {"kind": "component", "target": None}
                        else:
                            values[regs[0]] = None
                    elif name.startswith("move-result") and regs:
                        values[regs[0]], pending = pending, None
                    elif name.startswith("move-object") and len(regs) >= 2:
                        values[regs[0]] = values.get(regs[1])
                    elif name.startswith("invoke"):
                        pending = None
                        m = re.search(r'(L[^;]+;)->([^(]+)\(', out)
                        owner, api = (m.group(1), m.group(2)) if m else ("", "")
                        args = [(t, values.get(r) if r else None) for t, r in invoke_args(name, out, regs)]
                        obj = values.get(regs[0]) if regs and "static" not in name else None
                        first = args[0][1] if args else None
                        # 使用者觸發的 Intent (拍照、分享選單) 被拿去用 (啟動、查詢可處理的 App、交給 launcher) -> 同 method 的 URI 授權是使用者操作
                        if owner != "Landroid/content/Intent;" and any(
                                isinstance(v, dict) and v.get("kind") == "intent" and v.get("user") for _, v in args):
                            user_launch = True
                        if api == "getPackageName" and not args and is_context_class(dx, owner, context_cache):
                            # Context.getPackageName() 一定是自己; createPackageContext 拿到的是別的 App
                            pending = None if isinstance(obj, dict) and obj.get("kind") == "other_context" else own
                        elif api == "createPackageContext":
                            pending = {"kind": "other_context"}
                        elif owner == "Landroid/content/Intent;":
                            if api == "createChooser":
                                pending = dict(first if isinstance(first, dict) else new_intent(), user=True)
                            elif isinstance(obj, dict) and obj.get("kind") == "intent":
                                update_intent(obj, api, args, own)
                                # 建立 Intent 之後經過分支才指定接收者 -> 可能只有某條路徑有指定, 接收者不確定
                                if (api in ("setPackage", "setClass", "setClassName", "setComponent")
                                        and branches > obj.get("born", 0)):
                                    obj["target"] = "unknown"
                                if out.endswith(")Landroid/content/Intent;"):
                                    pending = obj   # builder 寫法 (putExtra 回傳同一個 Intent)
                        elif owner == "Landroid/content/ComponentName;" and api == "<init>" and isinstance(obj, dict):
                            types = [t for t, _ in args]
                            if "Landroid/content/Context;" in types:
                                obj["target"] = "self"
                            elif isinstance(first, str):
                                obj["target"] = "self" if first == own else first
                            else:
                                obj["target"] = "unknown"
                        elif api in BROADCAST_APIS and "LocalBroadcastManager;" not in owner:
                            intent = first
                            # 第二個參數是接收者要有的權限; const/4 0 (null) = 沒有
                            has_perm = len(args) > 1 and args[1][0] == "Ljava/lang/String;" and args[1][1] != 0
                            perm = args[1][1] if has_perm else None
                            if isinstance(perm, str) and perm in levels and not is_weak_level(levels[perm]):
                                continue   # 接收者要有 signature 等級權限, 其他 App 收不到
                            if not isinstance(intent, dict):
                                add(api, where, None, "review", "intent built in another method", ma)
                            elif intent["target"] == "self" or not (intent["payload"] or intent["grant"]) \
                                    or intent["action"] in SYSTEM_BROADCAST_ACTIONS:
                                continue
                            else:
                                key = next((k for k in intent.get("keys", []) if sensitive_keyword(k)), None)
                                sens = (True, "extra '%s'" % key) if key else None
                                if intent["target"] is None and not (has_perm and not isinstance(perm, str)) \
                                        and not (isinstance(perm, str) and perm not in levels):
                                    add(api, where, None, "high", "broadcast with data and no receiver", ma, sens)
                                else:
                                    add(api, where, intent["target"], "review",
                                        "receiver app or permission not confirmed", ma, sens)
                        elif api in ACTIVITY_LAUNCH_APIS:
                            # 開啟畫面是使用者看得到的操作, 不算自動分享; 只記錄有沒有啟動使用者觸發的 Intent
                            if isinstance(first, dict) and first.get("user"):
                                user_launch = True
                        elif api in SERVICE_LAUNCH_APIS:
                            intent = first
                            if (isinstance(intent, dict) and intent["target"] != "self"
                                    and (intent["payload"] or intent["grant"])):
                                add(api, where, intent["target"], "review", "data sent to a service of another app", ma)
                        elif api == "grantUriPermission" and first != own:
                            grants.append(first if isinstance(first, str) else None)
                    elif name.startswith(("if-", "goto", "packed-switch", "sparse-switch")):
                        branches += 1
                    elif name.startswith(("return", "iput", "sput", "aput", "check-cast", "monitor", "throw")):
                        continue
                    elif regs:
                        values.pop(regs[0], None)
                # grantUriPermission 常寫在 startActivity 之前, 整個 method 看完再判斷
                for target in grants if not user_launch else []:
                    add("grantUriPermission", where, target, "high", "URI access granted without user action", ma)
        return found

    def switch_getter(dx, out, cache):
        """invoke 的對象是「回傳 boolean 且裡面讀 SharedPreferences.getBoolean」的 App method (例 isShareEnabled()) -> 回傳該讀取
        使用: lab_039, lab_040 (透過 switch_reads), lab_087 (透過 store_switch_reads)"""
        m = re.search(r'(L[^;]+;)->([^(]+)(\([^)]*\)Z)$', out)
        if not m:
            return None
        key = (m.group(1), m.group(2), m.group(3).replace(" ", ""))
        if key not in cache:
            cache[key] = None
            ca = dx.classes.get(key[0])
            if ca is not None and not ca.is_external():
                for meth in ca.get_methods():
                    if meth.name == key[1] and str(meth.descriptor).replace(" ", "") == key[2]:
                        reads = [r for r in switch_reads(meth, dx, cache, getters=False)
                                 if r["api"] == "SharedPreferences"]
                        if reads:
                            cache[key] = {"key": reads[0]["key"], "default": reads[0]["default"],
                                          "api": "SharedPreferences"}
                        break
        return cache[key]

    def switch_reads(ma, dx, cache, getters=True):
        """一個 method 裡讀使用者開關的地方, 回傳 [{"key", "default", "api", "use"}]
        use: "branch" = 讀到的值拿來做 if 判斷; "passed" = 回傳 / 存欄位 / 傳給其他 method (在別處判斷, 看不到); "unused" = 讀了沒用
        SharedPreferences.getBoolean、回傳開關值的 App method (見 switch_getter) 都算; DataStore 看不到判斷, use 一律 "passed"
        使用: lab_039, lab_040 (透過 path_evidence), lab_087 (透過 store_switch_reads)"""
        try:
            instructions = [] if ma.is_external() else list(ma.get_method().get_instructions())
        except Exception:
            return []
        reads, consts, values, pending = [], {}, {}, None
        pending_res = None   # getString(R.string.xxx) 的資源編號, 當作開關 key (之後再轉成名稱)
        for ins in instructions:
            name, out = ins.get_name(), ins.get_output()
            regs = ins_registers(ins)
            if name.startswith("const-string") and regs:
                consts[regs[0]] = ins.get_string()
                values.pop(regs[0], None)
            elif name.startswith("const") and name != "const-class" and regs:
                try:
                    consts[regs[0]] = ins.get_literals()[0]
                except Exception:
                    consts.pop(regs[0], None)
                values.pop(regs[0], None)
            elif name.startswith("invoke"):
                for r in regs:
                    if r in values:
                        reads[values[r]]["passed"] = True
                pending, pending_res = None, None
                args = [r for _, r in invoke_args(name, out, regs)]
                if "->getString(I)Ljava/lang/String;" in out and args and isinstance(consts.get(args[0]), int):
                    pending_res = consts.get(args[0])
                if "Landroid/content/SharedPreferences;->getBoolean(" in out:
                    default = consts.get(args[1]) if len(args) > 1 else None
                    reads.append({"key": consts.get(args[0]) if args else None, "api": "SharedPreferences",
                                  "default": bool(default) if isinstance(default, int) else None,
                                  "branch": False, "passed": False})
                    pending = len(reads) - 1
                elif "Landroidx/datastore/preferences/core/Preferences;->get(" in out:
                    # 只建立 key (booleanKey) 不算, 要真的讀值
                    reads.append({"key": None, "api": "DataStore", "default": None, "branch": False, "passed": True})
                elif getters and out.endswith(")Z"):
                    hit = switch_getter(dx, out, cache)
                    if hit:
                        reads.append(dict(hit, branch=False, passed=False))
                        pending = len(reads) - 1
            elif name.startswith("move-result") and regs:
                if pending is not None:
                    values[regs[0]] = pending
                else:
                    values.pop(regs[0], None)
                if pending_res is not None:
                    consts[regs[0]] = pending_res
                else:
                    consts.pop(regs[0], None)
                pending, pending_res = None, None
            elif name.startswith("if-"):
                for r in regs:
                    if r in values:
                        reads[values[r]]["branch"] = True
            elif name.startswith(("return", "iput", "sput", "aput")):
                if regs and regs[0] in values:
                    reads[values[regs[0]]]["passed"] = True
            elif len(regs) >= 2 and regs[1] in values and name.startswith(("move", "xor-int", "not-int")):
                values[regs[0]] = values[regs[1]]   # 複製或取反 (!enabled)
            elif regs:
                values.pop(regs[0], None)
                consts.pop(regs[0], None)
        return [{"key": r["key"], "default": r["default"], "api": r["api"],
                 "use": "branch" if r["branch"] else ("passed" if r["passed"] else "unused")} for r in reads]

    def path_evidence(dx, start, cache, kind_of, depth=4, limit=300, reader=None):
        """從 start 的 method 往上追呼叫者 depth 層, 收集同意 / 開關證據
        kind_of(key) -> ("share", 名稱) 要找的開關 / ("other", 名稱) 其他用途的設定 / ("unknown", None) 看不出 key
        reader: 讀開關的函式, 預設 switch_reads (lab_087 用 store_switch_reads, 多認勾選框)
        回傳 {"dialog": 路徑經過對話框按鈕, "switch": 路徑讀了分享開關,
              "switch_unverified": 沒有分享開關, 但讀了看不出 key 的開關 (DataStore 等),
              "gating": "used" (開關值拿來判斷) / "unknown" (值傳到別處, 看不到) / "none" (讀了沒用) / None (沒開關),
              "keys": 分享開關名稱, "other_keys": 不算分享開關的設定名稱, "other_used": 其他設定的值有拿來做 if 判斷,
              "default_on": 分享開關預設是開}
        callback (run / onClick) 沒有呼叫者時, 改從建立該物件的地方 (<init> 的呼叫者) 繼續追
        使用: lab_039, lab_040 (透過 find_auto_share_channels), lab_087"""
        dialog, reads = False, []
        frontier, visited = list(start), set()
        for level in range(depth + 1):
            nxt = []
            for ma in frontier:
                key = (ma.class_name, ma.name, str(ma.descriptor))
                if key in visited or len(visited) >= limit:
                    continue
                visited.add(key)
                if ma.name == "onClick" and "Landroid/content/DialogInterface;" in str(ma.descriptor):
                    dialog = True
                if key not in cache["methods"]:
                    cache["methods"][key] = (reader or switch_reads)(ma, dx, cache["getters"])
                reads += cache["methods"][key]
                if level == depth:
                    continue
                try:
                    callers = [m for _, m, _ in ma.get_xref_from()]
                    if not callers and ma.class_name in dx.classes:
                        callers = [m for init in dx.classes[ma.class_name].get_methods() if init.name == "<init>"
                                   for _, m, _ in init.get_xref_from() if m.class_name != ma.class_name]
                except Exception:
                    callers = []
                nxt += callers
            frontier = nxt
        kinds = [(r, kind_of(r["key"])) for r in reads]
        share = [(r, k[1]) for r, k in kinds if k[0] == "share"]
        uses = {r["use"] for r, _ in share}
        gating = None
        if share:
            gating = "used" if "branch" in uses else ("unknown" if "passed" in uses else "none")
        return {"dialog": dialog, "switch": bool(share), "gating": gating,
                "switch_unverified": not share and any(k[0] == "unknown" for _, k in kinds),
                "keys": sorted({str(n) for _, n in share if n}),
                "other_keys": sorted({str(k[1]) for _, k in kinds if k[0] == "other"})[:5],
                "other_used": any(k[0] == "other" and r["use"] == "branch" for r, k in kinds),
                "default_on": any(r["default"] is True for r, _ in share)}

    def settings_switch_keys(a):
        """設定頁 XML (res/xml) 裡開關元件 (SwitchPreference 等) 的 key; 用來看程式讀的開關使用者看不看得到
        使用: lab_040 (透過 find_auto_share_channels)"""
        try:
            from androguard.core.axml import AXMLPrinter
        except ImportError:
            from androguard.core.bytecodes.axml import AXMLPrinter
        import xml.etree.ElementTree as ET
        keys = set()
        try:
            arsc = a.get_android_resources()
        except Exception:
            arsc = None
        for f in a.get_files():
            if not (f.startswith("res/xml") and f.endswith(".xml")):
                continue
            try:
                root = ET.fromstring(AXMLPrinter(a.get_file(f)).get_buff())
            except Exception:
                continue
            for el in root.iter():
                if not el.tag.split(".")[-1].endswith(SETTINGS_SWITCH_TAGS):
                    continue
                value = el.get(ANDROID_NS + "key") or el.get(APP_NS + "key")
                if value and value.startswith("@") and arsc is not None:
                    try:
                        value = arsc.get_resolved_res_configs(int(value[1:], 16))[0][1]
                    except Exception:
                        value = None
                if value:
                    keys.add(value)
        return keys

    def provider_code_evidence(dx, internal, keep, api_names):
        """看 provider class 的 method 與它們直接呼叫的 App method: 有沒有檢查呼叫者、是不是敏感資料
        回傳 {"caller_id": 有取得呼叫者身分, "caller_verified": 另外有比對簽章 / 權限, "sensitive": 說明或 None}
        使用: lab_039, lab_040 (透過 find_auto_share_channels)"""
        ca = dx.classes.get(internal)
        methods = [m for m in ca.get_methods() if not m.is_external()] if ca is not None else []
        callees = []
        for m in methods:
            try:
                callees += [c for _, c, _ in m.get_xref_to() if keep(c.class_name) and c.class_name != internal]
            except Exception:
                pass
        caller_id = caller_verified = False
        sensitive = None
        for m in methods + callees:
            try:
                outs = [] if m.is_external() else [ins.get_output() for ins in m.get_method().get_instructions()]
            except Exception:
                continue
            caller_id = caller_id or any(api in o for o in outs for api in CALLER_ID_APIS)
            caller_verified = caller_verified or any(api in o for o in outs for api in CALLER_VERIFY_APIS)
            sensitive = sensitive or method_sensitive_evidence(m, api_names)
        return {"caller_id": caller_id, "caller_verified": caller_verified, "sensitive": sensitive}

    def returns_data(ma):
        """method 會回傳物件 (有 return-object); 只丟例外 (UnsupportedOperationException) 的不算
        使用: lab_039, lab_040 (透過 find_auto_share_channels)"""
        try:
            return any(ins.get_name() == "return-object" for ins in ma.get_method().get_instructions())
        except Exception:
            return True

    def find_auto_share_channels(a, dx, keep):
        """找不用使用者操作就把資料交給其他 App 的管道, 並往上追呼叫路徑收集同意 / 開關證據
        1. exported provider, 讀取權限沒有或只是 normal / dangerous (其他 App 拿得到); 程式內比對呼叫者簽章 / 權限的不算
        2. 廣播、啟動背景元件、grantUriPermission (見 find_intent_channels)
        回傳 [{"type", "where", "target", "confidence" (high / review), "reason",
               "sensitive" (True / None), "sensitive_evidence", "evidence" (見 path_evidence + in_settings)}]
        使用: lab_039, lab_040"""
        root = a.get_android_manifest_xml()
        application = root.find("application") if root is not None else None
        if application is not None and application.get(ANDROID_NS + "enabled") == "false":
            return []
        levels = platform_permission_levels()
        for p in root.iter("permission") if root is not None else []:
            if p.get(ANDROID_NS + "name"):
                levels[p.get(ANDROID_NS + "name")] = p.get(ANDROID_NS + "protectionLevel") or ""
        try:
            target_sdk = int(a.get_target_sdk_version() or 0)
        except (TypeError, ValueError):
            target_sdk = 0
        app_permission = application.get(ANDROID_NS + "permission") if application is not None else None
        api_names = sensitive_api_names()

        channels = []
        for prov in root.iter("provider") if root is not None else []:
            name = prov.get(ANDROID_NS + "name")
            exported = (prov.get(ANDROID_NS + "exported") or "").lower()
            # 沒寫 exported: targetSdk >= 17 預設 false
            if not name or prov.get(ANDROID_NS + "enabled") == "false" or exported == "false" \
                    or (exported != "true" and target_sdk >= 17):
                continue
            full = resolve_activity_name(a.get_package() or "", name)
            internal = "L" + full.replace(".", "/") + ";"
            if not keep(internal):
                continue   # 第三方 SDK 的 provider
            # 讀取權限: readPermission 優先, 沒寫用 permission, 再沒寫用 <application> 的 permission
            read = prov.get(ANDROID_NS + "readPermission") or prov.get(ANDROID_NS + "permission") or app_permission
            if read and read in levels and not is_weak_level(levels[read]):
                continue   # signature 等級, 其他 App 拿不到
            declared = [m for m in dx.classes[internal].get_methods()
                        if m.name in PROVIDER_DATA_METHODS and not m.is_external()] if internal in dx.classes else []
            methods = [m for m in declared if returns_data(m)]
            if declared and not methods:
                continue   # 讀資料的 method 都只丟例外, 不提供資料
            code = provider_code_evidence(dx, internal, keep, api_names)
            if code["caller_id"] and code["caller_verified"]:
                continue   # 程式內比對呼叫者的簽章 / 權限, 只有特定 App 拿得到
            if read and read not in levels:
                confidence, reason = "review", "permission %s level unknown" % read
            elif not methods:
                confidence, reason = "review", "provider code not found"
            elif code["caller_id"]:
                confidence, reason = "review", "provider checks the calling app in code, effect not verified"
            else:
                confidence, reason = "high", "readable by other apps without permission" if not read \
                    else "permission %s is %s level" % (read, levels[read] or "normal")
            channels.append({"type": "provider", "where": full, "target": None, "confidence": confidence,
                             "reason": reason, "sensitive": True if code["sensitive"] else None,
                             "sensitive_evidence": code["sensitive"], "method": None, "start": methods})

        for c in find_intent_channels(a, dx, keep, levels):
            c["start"] = [c["method"]]
            channels.append(c)

        cache = {"methods": {}, "getters": {}}
        settings = settings_switch_keys(a) if channels else set()
        try:
            arsc = a.get_android_resources() if channels else None
        except Exception:
            arsc = None

        def kind_of(key):
            # 開關 key 是資源編號 (getString(R.string.xxx)) 時先轉成名稱
            if isinstance(key, int) and not isinstance(key, bool) and arsc is not None:
                try:
                    key = arsc.get_resolved_res_configs(key)[0][1]
                except Exception:
                    key = None
            if not isinstance(key, str) or not key:
                return ("unknown", None)
            # 只看 key 名稱; 設定頁有這個開關只列在細節, 不代表它是分享開關
            if SHARE_SWITCH_RE.search(split_words(key)):
                return ("share", key)
            return ("other", key)

        for c in channels:
            ev = path_evidence(dx, c.pop("start"), cache, kind_of)
            ev["in_settings"] = [k for k in ev["keys"] if k in settings]
            c["evidence"] = ev
            c.pop("method", None)
        return channels

    # App 自己讀取的敏感資料 -> 資料安全性類別
    # permissions: 需要的權限 (None = 不需權限); apis: 真正讀取資料的呼叫; strings: const-string 特徵
    # 使用: lab_041 (透過 find_sensitive_data_usage); lab_039, lab_040, lab_086, lab_087 (透過 sensitive_api_names)
    DATA_SAFETY_MAP = [
        {"name": "Location",
         "permissions": ["android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
                         "android.permission.ACCESS_BACKGROUND_LOCATION"],
         "categories": ["Location"],
         "apis": ["Landroid/location/LocationManager;->getLastKnownLocation", "Landroid/location/LocationManager;->requestLocationUpdates",
                  "Landroid/location/LocationManager;->getCurrentLocation", "Landroid/location/LocationManager;->requestSingleUpdate",
                  "Lcom/google/android/gms/location/FusedLocationProviderClient;->getLastLocation",
                  "Lcom/google/android/gms/location/FusedLocationProviderClient;->getCurrentLocation",
                  "Lcom/google/android/gms/location/FusedLocationProviderClient;->requestLocationUpdates",
                  "Landroid/location/Location;->getLatitude"]},
        {"name": "Contacts", "permissions": ["android.permission.READ_CONTACTS"],
         "categories": ["Contacts"], "apis": ["Landroid/provider/ContactsContract"]},
        {"name": "SMS", "permissions": ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS"],
         "categories": ["Messages"], "apis": ["Landroid/provider/Telephony$Sms", "Landroid/telephony/SmsMessage;->"]},
        {"name": "Calendar", "permissions": ["android.permission.READ_CALENDAR"],
         "categories": ["Calendar"], "apis": ["Landroid/provider/CalendarContract"]},
        {"name": "Microphone", "permissions": ["android.permission.RECORD_AUDIO"],
         "categories": ["Audio"],
         "apis": ["Landroid/media/AudioRecord;->startRecording", "Landroid/media/MediaRecorder;->setAudioSource",
                  "Landroid/speech/SpeechRecognizer;->startListening"]},
        {"name": "Audio files", "permissions": ["android.permission.READ_MEDIA_AUDIO", "android.permission.READ_EXTERNAL_STORAGE"],
         "categories": ["Audio"], "apis": ["Landroid/provider/MediaStore$Audio"]},
        {"name": "Camera", "permissions": ["android.permission.CAMERA"],
         "categories": ["Photos and videos"],
         "apis": ["Landroid/hardware/camera2/CameraManager;->openCamera", "Landroid/hardware/Camera;->open",
                  "Landroidx/camera/core/ImageCapture;->takePicture", "Landroidx/camera/lifecycle/ProcessCameraProvider;->bindToLifecycle"]},
        {"name": "Photos", "permissions": ["android.permission.READ_MEDIA_IMAGES", "android.permission.READ_MEDIA_VIDEO",
                                           "android.permission.READ_EXTERNAL_STORAGE"],
         "categories": ["Photos and videos"], "apis": ["Landroid/provider/MediaStore$Images", "Landroid/provider/MediaStore$Video"]},
        {"name": "Phone identifiers", "permissions": ["android.permission.READ_PHONE_STATE"],
         "categories": ["Device or other IDs"],
         "apis": ["Landroid/telephony/TelephonyManager;->getDeviceId", "Landroid/telephony/TelephonyManager;->getImei",
                  "Landroid/telephony/TelephonyManager;->getMeid", "Landroid/telephony/TelephonyManager;->getSubscriberId",
                  "Landroid/telephony/TelephonyManager;->getSimSerialNumber"]},
        {"name": "Phone number", "permissions": ["android.permission.READ_PHONE_STATE", "android.permission.READ_PHONE_NUMBERS", "android.permission.READ_SMS"],
         "categories": ["Personal info"], "apis": ["Landroid/telephony/TelephonyManager;->getLine1Number",
                                                   "Landroid/telephony/SubscriptionManager;->getPhoneNumber"]},
        {"name": "Accounts", "permissions": ["android.permission.GET_ACCOUNTS"],
         "categories": ["Personal info"], "apis": ["Landroid/accounts/AccountManager;->getAccounts"]},
        {"name": "Advertising ID", "permissions": None,
         "categories": ["Device or other IDs"],
         "apis": ["Lcom/google/android/gms/ads/identifier/AdvertisingIdClient;->getAdvertisingIdInfo"]},
        {"name": "Android ID", "permissions": None,
         "categories": ["Device or other IDs"], "strings": ["android_id"]},
    ]

    # 第三方 SDK 本身就會收集並傳出的資料類別 (依各 SDK 官方的資料安全性說明, 只列確定會收集的)
    # 每個類別都要各自聲明
    # 使用: lab_041 (透過 find_sensitive_data_usage)
    DATA_SAFETY_SDKS = [
        ("Lcom/google/firebase/analytics/",         "Firebase Analytics",   ["App activity", "Device or other IDs"]),
        ("Lcom/google/android/gms/analytics/",      "Google Analytics",     ["App activity", "Device or other IDs"]),
        ("Lcom/google/firebase/crashlytics/",       "Firebase Crashlytics", ["App info and performance"]),
        ("Lcom/google/android/gms/ads/MobileAds;",  "Google Mobile Ads",    ["Device or other IDs"]),
        ("Lcom/facebook/appevents/",                "Facebook App Events",  ["App activity", "Device or other IDs"]),
        ("Lcom/appsflyer/",                         "AppsFlyer",            ["Device or other IDs"]),
        ("Lcom/adjust/sdk/",                        "Adjust",               ["Device or other IDs"]),
        ("Lio/sentry/",                             "Sentry",               ["App info and performance"]),
        ("Lcom/onesignal/",                         "OneSignal",            ["Device or other IDs"]),
    ]

    # App 自己的程式碼發出網路請求的呼叫
    # 使用: lab_041 (透過 find_sensitive_data_usage)
    NETWORK_API_TOKENS = ("Ljava/net/URL;->openConnection", "Lokhttp3/OkHttpClient;->newCall", "Lretrofit2/Retrofit$Builder;->baseUrl",
                          "Lcom/android/volley/RequestQueue;->add", "Ljava/net/Socket;-><init>", "Lio/ktor/client/")

    # 資料安全性頁面的類別名稱 (英文); 只認這些, 其他標題不算
    # 使用: lab_041 (透過 fetch_play_data_safety)
    PLAY_DATA_CATEGORIES = {
        "location", "personal info", "financial info", "health and fitness", "messages", "photos and videos",
        "audio", "files and docs", "calendar", "contacts", "app activity", "web browsing",
        "app info and performance", "device or other ids",
    }

    # 掃碼函式庫; 有這些又沒拍照存檔時, 相機可能只用來掃 QR code, 不一定會傳出照片
    # 使用: lab_041 (透過 find_sensitive_data_usage)
    BARCODE_SDK_PREFIXES = ("Lcom/google/zxing/", "Lcom/journeyapps/barcodescanner/", "Lcom/google/mlkit/vision/barcode/",
                            "Lcom/google/android/gms/vision/barcode/", "Lcom/huawei/hms/scankit/", "Lnet/sourceforge/zbar/")

    # 在 Manifest 關閉 SDK 自動收集的 meta-data: (名稱, 代表關閉的值)
    # 使用: lab_041 (透過 find_sensitive_data_usage)
    SDK_DISABLE_FLAGS = {
        "Firebase Analytics":   [("firebase_analytics_collection_deactivated", "true"),
                                 ("firebase_analytics_collection_enabled", "false")],
        "Firebase Crashlytics": [("firebase_crashlytics_collection_enabled", "false")],
        "Facebook App Events":  [("com.facebook.sdk.AutoLogAppEventsEnabled", "false")],
    }

    def find_sensitive_data_usage(a, dx, keep):
        """找要在資料安全性聲明的資料, 回傳 (network, usages)
        network: App 自己的程式碼有發網路請求 (且有 INTERNET 權限)
        usages: [{"kind": "app" / "sdk", "source", "categories", "where", "review" (有值 = 待確認的原因)}]
          app = App 自己讀取的敏感資料 (有權限 + 程式碼真的讀取); sdk = 會收集資料的第三方 SDK (每個類別一筆)
        使用: lab_041"""
        perms = set(a.get_permissions())
        network = "android.permission.INTERNET" in perms and bool(find_app_references(dx, keep, NETWORK_API_TOKENS))

        def where_of(cls, meth):
            return "%s.%s" % (cls[1:-1].replace("/", "."), meth)

        usages = []
        active = [e for e in DATA_SAFETY_MAP if e["permissions"] is None or perms & set(e["permissions"])]
        api_tokens = [t for e in active for t in e.get("apis", [])]
        refs = strip_instructions(find_app_references(dx, keep, api_tokens)) if api_tokens else []
        str_tokens = {s for e in active for s in e.get("strings", [])}
        strs = find_app_const_strings(dx, lambda s: s if s in str_tokens else None, keep) if str_tokens else []
        scanner = bool(find_class_prefixes(dx, [(p, "") for p in BARCODE_SDK_PREFIXES]))
        for e in active:
            hits = [r for r in refs if r["api"] in e.get("apis", [])]
            hit = hits[0] if hits else None
            if hit:
                where = where_of(hit["class"], hit["method"])
            else:
                s = next((x for x in strs if x["indicator"] in e.get("strings", [])), None)
                if not s:
                    continue
                where = where_of(s["class"], s["method"])
            source = sorted(perms & set(e["permissions"]))[0] if e["permissions"] else e["name"]
            usage = {"kind": "app", "source": source, "categories": e["categories"], "where": where,
                     "locations": len(hits) or 1}
            if e["name"] == "Camera" and scanner and not any("takePicture" in r["api"] for r in hits):
                usage["review"] = "camera may only be used to scan codes"
            usages.append(usage)

        meta = {m.get(ANDROID_NS + "name"): (m.get(ANDROID_NS + "value") or "").lower()
                for m in a.get_android_manifest_xml().iter("meta-data")}
        for prefix, sdk, cats in DATA_SAFETY_SDKS:
            # 只算真的打包進 APK 的 SDK, 只有引用到的不算
            if not any(cls.startswith(prefix) and not ca.is_external() for cls, ca in dx.classes.items()):
                continue
            disabled = any(meta.get(k) == v for k, v in SDK_DISABLE_FLAGS.get(sdk, []))
            for c in cats:
                usage = {"kind": "sdk", "source": "SDK " + sdk, "categories": [c], "where": ""}
                if disabled:
                    usage["review"] = "collection disabled in manifest"
                usages.append(usage)
        return network, usages

    def parse_play_data_safety(html):
        """解析資料安全性頁面: 從標題 (h1-h4, 可含巢狀標籤) 找出已聲明的類別; 看不懂的頁面回 parse_failed, 不當作沒聲明
        回傳 {"status": ok / parse_failed, "declared"}
        使用: lab_041 (透過 fetch_play_data_safety)"""
        from html.parser import HTMLParser

        class SafetyParser(HTMLParser):
            def __init__(self):
                super().__init__(convert_charrefs=True)
                self.headings, self.text, self.parts, self.heading = [], [], [], None
                self.hidden = 0
            def handle_starttag(self, tag, attrs):
                if tag in ('script', 'style'):
                    self.hidden += 1
                if tag in ('h1', 'h2', 'h3', 'h4') and not self.hidden:
                    self.heading, self.parts = tag, []
            def handle_endtag(self, tag):
                if tag in ('script', 'style'):
                    self.hidden = max(0, self.hidden - 1)
                if tag == self.heading:
                    self.headings.append(' '.join(''.join(self.parts).split()))
                    self.heading = None
            def handle_data(self, value):
                if not self.hidden:
                    self.text.append(value)
                    if self.heading:
                        self.parts.append(value)

        parser = SafetyParser()
        parser.feed(html)
        visible = ' '.join(' '.join(parser.text).split()).lower()
        if 'data safety' not in visible:
            return {"status": "parse_failed", "declared": []}
        categories = sorted({h for h in parser.headings if h.lower() in PLAY_DATA_CATEGORIES})
        # 「收集」與「分享」的類別合併計算
        if categories and ('data collected' in visible or 'data shared' in visible):
            return {"status": "ok", "declared": categories}
        if not categories and 'no data collected' in visible and 'no data shared' in visible:
            return {"status": "ok", "declared": []}
        return {"status": "parse_failed", "declared": []}

    def fetch_play_data_safety(package):
        """抓 Google Play 資料安全性頁面, 回傳 {"status", "declared" (已聲明類別), "url", "fetched_at"}
        status: ok / not_on_play / fetch_failed / parse_failed / invalid_package
        使用: lab_041, lab_086 (透過 storage_consent_analyze)"""
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+', package or ''):
            return {"status": "invalid_package", "declared": []}
        import hashlib
        url = "https://play.google.com/store/apps/datasafety?id=%s&hl=en&gl=US" % package
        metadata = {"url": url, "fetched_at": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", "Accept-Language": "en-US,en;q=0.9"})
        try:
            with urllib.request.urlopen(req, timeout=15) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                return dict(metadata, status="parse_failed", declared=[])
            html = raw.decode('utf-8', 'replace')
        except urllib.error.HTTPError as e:
            return dict(metadata, status="not_on_play" if e.code == 404 else "fetch_failed", declared=[])
        except Exception:
            return dict(metadata, status="fetch_failed", declared=[])
        metadata['content_sha256'] = hashlib.sha256(raw).hexdigest()
        if re.search(r'<title[^>]*>\s*Not Found\s*</title>', html, re.I):
            return dict(metadata, status="not_on_play", declared=[])
        return dict(metadata, **parse_play_data_safety(html))

    # ---- 程式碼混淆 ----

    # class / method / field 任一短名稱比例達到就算有混淆
    # F-Droid 等 13 個對照 APK 實測 (2026-10-06): 未混淆最高 0.08, 有混淆最低 0.66
    # 使用: lab_084
    OBF_RATIO_THRESHOLD = 0.3

    # App 自己套件的 class 少於這個數不判斷 (多半是加殼, 程式碼執行時才載入)
    # 使用: lab_084, lab_016 (透過 lib_code_hidden)
    OBF_MIN_CLASSES = 10

    # App 自己的套件幾乎沒有 class 時, 改看被搬到 o、a.b 這類短套件的 class: 達到這個數 -> 程式碼被混淆工具搬走
    # (DexGuard / R8 repackageclasses), 算有混淆; 自己的套件看得到時不看 (搬走的多半是函式庫, 不代表 App 程式碼有混淆)
    # 16 個對照 APK 實測 (2026-10-09): 兆豐 (DexGuard) 1765 個, 元大 (加殼) 0 個
    # 使用: lab_084, lab_016 (透過 lib_code_hidden)
    OBF_REPACKAGED_MIN = 50

    # 兩個字母但常見的真實頂層套件 (國碼、io), 不當作搬移後的短套件
    # 使用: lab_084 (透過 is_repackaged_class)
    OBF_REAL_SHORT_PACKAGES = {"io", "me", "tv", "de", "jp", "uk", "fr", "nl", "kr", "cn", "tw", "ru", "in", "it",
                               "es", "co", "eu", "us", "ca", "br", "pl", "se", "ch", "at", "be", "dk", "fi", "no"}

    # 混淆工具產生的短名稱: a、B、aa、a1、ab12
    # 使用: lab_084 (透過 is_obfuscated_name)
    OBF_SHORT_NAME_RE = re.compile(r'^[A-Za-z]{1,2}\d{0,3}$')

    # 不會是 App 自己套件的前綴
    # 使用: lab_084 (透過 app_own_prefixes)
    OBF_LIB_PREFIXES = ("Landroid/", "Landroidx/", "Lcom/google/", "Lkotlin/", "Lkotlinx/", "Ljava/", "Ljavax/", "Lj$/")

    # 混淆工具不會改名的 method (覆寫 Java / Android 的方法)
    # 使用: lab_084 (透過 obfuscation_stats)
    OBF_SKIP_METHODS = {"values", "valueOf", "toString", "equals", "hashCode", "run", "call", "invoke", "get", "set"}

    def is_obfuscated_name(name):
        """名稱是否像混淆後的識別字 (a、aa、a1、Il1l 組合、非 ASCII)
        使用: lab_084 (透過 obfuscation_stats)"""
        return bool(OBF_SHORT_NAME_RE.match(name)) or any(ord(ch) > 127 for ch in name) \
            or (len(name) >= 3 and set(name) <= set("Il1"))

    def is_repackaged_class(class_name):
        """class 被混淆工具搬到短套件: 頂層套件是單一字母 (o.X、a.b.C), 或套件每層都 <= 2 字且 class 名稱也是短名稱
        使用: lab_084 (透過 obfuscation_stats), lab_016 (透過 lib_code_hidden)"""
        parts = class_name[1:-1].split("/")
        if len(parts) < 2 or class_name.startswith(OBF_LIB_PREFIXES):
            return False
        packages, simple = parts[:-1], parts[-1].split("$")[0]
        if len(packages[0]) == 1:
            return True
        return (packages[0] not in OBF_REAL_SHORT_PACKAGES and all(len(p) <= 2 for p in packages)
                and is_obfuscated_name(simple))

    def app_own_prefixes(a):
        """App 自己的套件前綴: Manifest package 與啟動 Activity 的套件 (最多 3 層)
        不用 Application class (加殼時是殼的 class); 第三方的元件也不算
        使用: lab_084 (透過 obfuscation_stats), lab_086, lab_087 (透過 storage_consent_result), lab_016 (透過 lib_code_hidden)"""
        package = a.get_package() or ""
        prefixes = set()
        names = [(package, False)]
        main = a.get_main_activity()
        if main:
            names.append((resolve_activity_name(package, main), True))
        for name, is_class in names:
            parts = [p for p in name.split(".") if p]
            if is_class:
                parts = parts[:-1]
            parts = parts[:3]
            prefix = "L" + "/".join(parts) + "/"
            if len(parts) >= 2 and not prefix.startswith(OBF_LIB_PREFIXES):
                prefixes.add(prefix)
        return tuple(sorted(prefixes))

    def obfuscation_stats(a, dx):
        """統計 App 自己套件的混淆程度; 排除編譯器產生的 (synthetic)、JNI、R / BuildConfig;
        Manifest 元件的 class 名稱必須保留, 只算它的 method / field
        回傳 scanned_app_classes、class / method / field_ratio 與名稱範例
        使用: lab_084"""
        package = a.get_package() or ""
        prefixes = app_own_prefixes(a)
        components = set()
        for name in (a.get_activities() + a.get_services() + a.get_receivers() + a.get_providers()
                     + [a.get_attribute_value("application", "name")]):
            if name:
                components.add("L" + resolve_activity_name(package, name).replace(".", "/") + ";")

        def last_name(simple):
            # Outer$Inner$1 -> Inner (匿名 class 的數字不算)
            parts = [p for p in simple.split("$") if p and not p.isdigit()]
            return parts[-1] if parts else simple

        scanned = 0
        short_classes, plain_classes = [], []
        m_total = m_short = f_total = f_short = 0
        for class_name, ca in dx.classes.items():
            if ca.is_external() or not prefixes or not class_name.startswith(prefixes):
                continue
            vm_class = ca.get_vm_class()
            simple = class_name[1:-1].rsplit("/", 1)[-1]
            if vm_class.get_access_flags() & 0x1000 or simple in ("R", "BuildConfig") \
                    or simple.startswith("R$") or "$$" in simple:
                continue
            methods = [m.get_method() for m in ca.get_methods() if not m.is_external()]
            # native method 依名稱綁定 JNI, 不能改名
            if any(m.get_access_flags() & 0x100 for m in methods):
                continue
            scanned += 1
            if class_name not in components:
                (short_classes if is_obfuscated_name(last_name(simple)) else plain_classes).append(class_name)
            for m in methods:
                name = m.get_name()
                if m.get_access_flags() & 0x1000 or name.startswith("<") or "$" in name or name in OBF_SKIP_METHODS:
                    continue
                m_total += 1
                m_short += is_obfuscated_name(name)
            for f in vm_class.get_fields():
                name = f.get_name()
                if f.get_access_flags() & 0x1000 or "$" in name or \
                        name in ("serialVersionUID", "CREATOR", "INSTANCE", "Companion"):
                    continue
                f_total += 1
                f_short += is_obfuscated_name(name)

        # 搬到短套件的 class (不在 App 自己的套件裡, 上面沒算到)
        repackaged = [c for c, ca in dx.classes.items()
                      if not ca.is_external() and not (prefixes and c.startswith(prefixes)) and is_repackaged_class(c)]

        c_total = len(short_classes) + len(plain_classes)
        return {
            "own_prefixes":        list(prefixes),
            "scanned_app_classes": scanned,
            "repackaged_classes":  len(repackaged),
            "repackaged_examples": sorted(repackaged)[:5],
            "class_ratio":  round(len(short_classes) / c_total, 3) if c_total else 0.0,
            "method_ratio": round(m_short / m_total, 3) if m_total else 0.0,
            "field_ratio":  round(f_short / f_total, 3) if f_total else 0.0,
            "counts": {"classes": c_total, "short_classes": len(short_classes), "methods": m_total,
                       "short_methods": m_short, "fields": f_total, "short_fields": f_short},
            "plain_examples":      sorted(plain_classes)[:10],
            "obfuscated_examples": sorted(short_classes)[:10],
        }

    # ---- 交易管道 ----

    # 第三方支付 SDK (結帳畫面由 SDK 顯示, 內容看不到); (class 前綴, 名稱)
    # 使用: lab_085 (透過 find_payment_channels)
    PAYMENT_SDK_PREFIXES = [
        ("Lcom/stripe/android/",                 "Stripe"),
        ("Lcom/paypal/",                         "PayPal"),
        ("Lcom/braintreepayments/api/",          "Braintree"),
        ("Lcom/adyen/checkout/",                 "Adyen"),
        ("Lcom/razorpay/",                       "Razorpay"),
        ("Ltech/cherri/tpdirect/",               "TapPay"),
        ("Lcom/samsung/android/sdk/samsungpay/", "Samsung Pay"),
        ("Lsqip/",                               "Square In-App Payments"),
        ("Lcom/airwallex/android/",              "Airwallex"),
        ("Lio/primer/android/",                  "Primer"),
        ("Lcom/processout/sdk/",                 "ProcessOut"),
        ("Lco/omise/android/",                   "Omise"),
        ("Lco/xendit/",                          "Xendit"),
        ("Lcom/judopay/judokit/",                "Judopay"),
        ("Lcom/paysafe/android/",                "Paysafe"),
        ("Lcom/recurly/androidsdk/",             "Recurly"),
        ("Lpayment/sdk/android/",                "Network International"),
    ]

    # 只有 App 自己呼叫才算的支付 API (SDK 也用在分享 / 登入, 只看到 class 不算); (API, 名稱)
    # 使用: lab_085 (透過 find_payment_channels)
    PAYMENT_CALL_APIS = [
        ("Lcom/alipay/sdk/app/PayTask;->",         "Alipay"),
        ("Lcom/tencent/mm/opensdk/modelpay/PayReq", "WeChat Pay"),
    ]

    # Activity 名稱含這些字 -> 可能是自建交易畫面
    # transfer 單獨出現不算 (常見於資料傳輸, 如 TransferEntriesActivity)
    # 使用: lab_085 (透過 find_payment_channels)
    TRANSACTION_SCREEN_WORDS = {"checkout", "payment", "pay", "purchase", "remit", "remittance", "order",
                                "trade", "trading", "topup", "recharge", "cart", "transaction", "redeem", "redemption", "voucher"}

    # 套件名 / App 名稱含這些字 -> 金融 App, 交易畫面可能看不到 (單一 Activity、Flutter、加殼)
    # 使用: lab_085 (透過 find_payment_channels)
    FINANCE_APP_WORDS = ("bank", "pay", "wallet", "securities", "stock", "invest", "finance", "trade", "broker",
                         "futures", "crypto", "銀行", "支付", "錢包", "證券", "金融", "投信", "期貨", "交易")

    # 網頁金流的付款網址 (App 開網頁或導轉付款); (網址片段, 名稱), 網址以官方技術文件為準
    # 使用: lab_085 (透過 find_payment_channels)
    PAYMENT_GATEWAY_URLS = [
        ("payment.ecpay.com.tw",       "ECPay"),       # 綠界 AioCheckOut (含 payment-stage 測試環境)
        ("payment-stage.ecpay.com.tw", "ECPay"),
        ("core.newebpay.com",          "NewebPay"),    # 藍新 MPG (ccore 為測試環境)
        ("api-pay.line.me",            "LINE Pay"),    # LINE Pay Online API (含 sandbox-api-pay)
        ("checkout.stripe.com",        "Stripe Checkout"),
        ("paypal.com/checkoutnow",     "PayPal Checkout"),
    ]

    # 其他應用商店的內購 (購買畫面由商店顯示商品、金額、付款方式, 同 Google Play 內購); (App 呼叫的 API, 名稱), API 以官方文件為準
    # 使用: lab_085 (透過 find_payment_channels)
    STORE_BILLING_APIS = [
        ("Lcom/huawei/hms/iap/IapClient;->createPurchaseIntent", "Huawei IAP"),
        ("/IapHelper;->startPayment(",                          "Samsung IAP"),
        ("Lcom/amazon/device/iap/PurchasingService;->purchase(", "Amazon IAP"),
    ]

    # 台灣常見電子支付 App (跳到錢包 App 付款); 套件名稱以 Google Play 頁面為準 (2026-10-19 查證)
    # 出現在 Manifest <queries> 或 App 程式碼字串 -> 會跳到該 App 付款
    # 使用: lab_085 (透過 find_payment_channels)
    WALLET_APP_PACKAGES = {
        "com.jkos.app":            "JKOPay 街口支付",
        "com.pxpayplus.app":       "PX Pay Plus 全支付",
        "com.easycard.wallet":     "Easy Wallet 悠遊付",
        "com.linepaytw.upay":      "LINE Pay",
        "tw.com.icash.a.icashpay": "icash Pay",
        "com.ipass.ipassmoney":    "iPASS MONEY",
        "tw.com.twmp.twhcewallet": "Taiwan Pay 台灣Pay",
    }

    # 交易專用的介面文字 (字串資源的內容): MAS 3.6 交易資源含實體貨幣、點數 / 序號、票券 / 股票
    # 只用交易才會出現的詞組; 「購買」「Buy」太常見 (內購 App 也有)、「check out」常是「看看」(分享文字) 不用
    # 使用: lab_085 (透過 find_transaction_text)
    TRANSACTION_TEXT_ZH = ("確認付款", "付款方式", "支付方式", "結帳", "確認轉帳", "轉帳金額", "確認交易", "交易密碼",
                           "委託買進", "委託賣出", "確認下單", "兌換點數", "點數兌換", "確認兌換", "儲值金額", "加值金額",
                           "立即儲值", "購票", "訂票", "付款金額", "應付金額", "訂單金額")
    TRANSACTION_TEXT_EN = re.compile(r'\b(confirm payment|payment method|place order|checkout|top[ -]?up|redeem points|'
                                     r'order total|amount due|pay now)\b', re.I)

    # 信用卡輸入欄位: 資源名稱拆字後有這些字 (CVV / CVC 只出現在刷卡付款), 或字串有「末三碼」
    # 只有卡號、有效期限不算 (會員卡、憑證到期也會用到)
    # 使用: lab_085 (透過 find_card_form)
    CARD_CVV_WORDS = {"cvv", "cvv2", "cvc", "cvc2", "cvn", "cvn2"}
    CARD_CVV_TEXT_RE = re.compile(r'末三碼|背面.{0,4}三碼')

    # Google Pay 請求可能寫在資源檔 (res/raw、assets 的 JSON)
    # 使用: lab_085 (透過 apk_text_files)
    PAYMENT_JSON_MAX = 512 * 1024

    def apk_text_files(a, prefixes, suffixes):
        """APK 裡指定位置的文字檔內容 [(路徑, 文字)]; 讀不到的略過
        使用: lab_085"""
        out = []
        try:
            files = [f for f in a.get_files() if isinstance(f, str)]
        except Exception:
            return out
        for path in files:
            if path.startswith(prefixes) and path.endswith(suffixes):
                try:
                    raw = a.get_file(path)
                except Exception:
                    continue
                if isinstance(raw, bytes) and len(raw) <= PAYMENT_JSON_MAX:
                    out.append((path, raw.decode('utf-8', 'replace')))
        return out

    def find_transaction_text(a):
        """字串資源內容裡的交易專用詞組 -> 有交易畫面 (含點數兌換、儲值、購票、證券下單); 回傳 [(資源名稱, 詞組)] 最多 5 個
        使用: lab_085 (透過 find_payment_channels)"""
        try:
            xml = a.get_android_resources().get_string_resources(a.get_package())
        except Exception:
            return []
        text = xml.decode('utf-8', 'replace') if isinstance(xml, bytes) else str(xml)
        hits = []
        for name, value in re.findall(r'<string name="([^"]+)">([^<]*)</string>', text):
            word = next((w for w in TRANSACTION_TEXT_ZH if w in value), None)
            if not word:
                m = TRANSACTION_TEXT_EN.search(value)
                word = m.group(0) if m else None
            if word and len(value) <= 60:
                hits.append((name, word))
        seen, out = set(), []
        for name, word in hits:
            if word.lower() not in seen:
                seen.add(word.lower())
                out.append((name, word))
        return out[:5]

    def wallet_app_targets(a, dx, keep):
        """Manifest <queries> 與 App 程式碼字串裡的電子支付 App 套件名稱 -> {名稱: 位置}
        使用: lab_085 (透過 find_payment_channels)"""
        found = {}
        try:
            ns = '{http://schemas.android.com/apk/res/android}'
            for q in a.get_android_manifest_xml().iter('queries'):
                for pkg in q.iter('package'):
                    name = WALLET_APP_PACKAGES.get(pkg.get(ns + 'name') or '')
                    if name:
                        found.setdefault(name, 'AndroidManifest <queries>')
        except Exception:
            pass
        for hit in find_app_const_strings(dx, lambda s: WALLET_APP_PACKAGES.get((s or '').strip()), keep):
            found.setdefault(hit["indicator"], hit["class"])
        return found

    def find_card_form(a):
        """資源 (id、字串名稱與內容) 裡的信用卡安全碼欄位 -> 自建刷卡畫面; 回傳命中的名稱 (最多 5 個)
        使用: lab_085 (透過 find_payment_channels)"""
        try:
            res = a.get_android_resources()
            package = a.get_package()
            xml = res.get_id_resources(package) + res.get_string_resources(package)
        except Exception:
            return []
        text = xml.decode('utf-8', 'replace') if isinstance(xml, bytes) else str(xml)
        hits = set()
        for name in re.findall(r'name="([^"]+)"', text):
            words = {w.lower() for w in re.findall(r'[A-Z]?[a-z]+[0-9]*|[A-Z]+[0-9]*(?![a-z])', name)}
            if words & CARD_CVV_WORDS:
                hits.add(name)
        hits.update(m.group(0) for m in CARD_CVV_TEXT_RE.finditer(text))
        return sorted(hits)[:5]

    def hce_payment_info(a, service):
        """NFC 卡片模擬服務的設定 (apduservice.xml): 回傳 (是否為付款類, 是否要求解鎖); 讀不到回傳 (None, None)
        使用: lab_085 (透過 find_payment_channels)"""
        ns = '{http://schemas.android.com/apk/res/android}'
        try:
            from androguard.core.axml import AXMLPrinter
            manifest = a.get_android_manifest_xml()
            res = a.get_android_resources()
            for svc in manifest.iter('service'):
                name = svc.get(ns + 'name') or ''
                if resolve_activity_name(a.get_package() or '', name) != resolve_activity_name(a.get_package() or '', service):
                    continue
                for md in svc.iter('meta-data'):
                    if md.get(ns + 'name') != 'android.nfc.cardemulation.host_apdu_service':
                        continue
                    rid = int((md.get(ns + 'resource') or '').lstrip('@'), 16)
                    for _, path in res.get_resolved_res_configs(rid)[:1]:
                        root = AXMLPrinter(a.get_file(path)).get_xml_obj()
                        payment = any(g.get(ns + 'category') == 'payment' for g in root.iter('aid-group'))
                        unlock = (root.get(ns + 'requireDeviceUnlock') or '').lower() == 'true'
                        return payment, unlock
        except Exception:
            pass
        return None, None

    def find_payment_channels(a, dx, keep):
        """找 App 的交易管道, 每個管道: type / where / evidence / problem (None = 沒問題) / confidence (high 或 review)
        Google Play 內購 -> 沒問題; Google Pay (App 自己呼叫的) -> 依請求內容判斷; 第三方 SDK (含 SDK 內部呼叫的 Google Pay)、NFC 感應支付、自建交易畫面、找不到畫面的金融 App -> review
        使用: lab_085"""
        channels = []

        # 1. Google Play 內購: 平台購買畫面一定顯示商品、金額、付款方式
        billing = strip_instructions(find_app_references(dx, keep, [
            "Lcom/android/billingclient/api/BillingClient;->launchBillingFlow"]))
        billing_lib = find_class_prefixes(dx, [("Lcom/android/billingclient/", "Google Play Billing Library")])
        billing_perm = "com.android.vending.BILLING" in a.get_permissions()
        # 只宣告權限、沒有函式庫也沒呼叫, 不算有內購
        if billing or billing_lib:
            channels.append({"type": "google_play_billing",
                             "where": billing[0]["class"] if billing else "Google Play Billing",
                             "evidence": {"launch_calls": billing[:5], "library": bool(billing_lib),
                                          "permission": billing_perm},
                             "problem": None, "confidence": "high"})

        # 1b. 其他應用商店的內購 (華為、Samsung、Amazon): 由商店顯示交易資訊, 同 Google Play 內購
        store = strip_instructions(find_app_references(dx, keep, [api for api, _ in STORE_BILLING_APIS]))
        for name in sorted({n for api, n in STORE_BILLING_APIS for r in store if r["api"] == api}):
            refs = [r for r in store if next(n for api, n in STORE_BILLING_APIS if api == r["api"]) == name]
            channels.append({"type": "store_billing", "where": "%s (%s)" % (name, refs[0]["class"]),
                             "evidence": {"calls": refs[:5]}, "problem": None, "confidence": "high"})
        billing = billing + store

        # 2. Google Pay: 檢查 App 自己組的請求有沒有 MAS 要求的商品名稱 (displayItems)、金額 (totalPrice)、交易方式 (allowedPaymentMethods)
        #    支付 SDK 內部呼叫 Google Pay 的不算 (請求由 SDK 組, 歸到第 3 類)
        sdk_prefixes = tuple(prefix for prefix, _ in PAYMENT_SDK_PREFIXES)

        def own(class_name):
            return keep(class_name) and not class_name.startswith(sdk_prefixes)

        gpay = strip_instructions(find_app_references(dx, own, [
            "Lcom/google/android/gms/wallet/PaymentsClient;->loadPaymentData"]))
        if gpay:
            keys = ("totalPrice", "displayItems", "allowedPaymentMethods", "transactionInfo", "totalPriceStatus")

            def match(s):
                s = s or ""
                hits = [k for k in keys if s == k or ('"%s"' % k) in s]
                return ",".join(hits) or None

            found = set()
            for hit in find_app_const_strings(dx, match, own):
                found.update(hit["indicator"].split(","))
            # 請求寫在 res/raw、assets 的 JSON
            for path, text in apk_text_files(a, ('res/raw/', 'assets/'), ('.json', '.txt')):
                if '"allowedPaymentMethods"' in text or '"transactionInfo"' in text:
                    found.update(k for k in keys if ('"%s"' % k) in text)
            # 舊版 Builder 寫法
            for ref in find_app_references(dx, own, [
                    "Lcom/google/android/gms/wallet/TransactionInfo$Builder;->setTotalPrice(",   # 不含 setTotalPriceStatus
                    "Lcom/google/android/gms/wallet/TransactionInfo$Builder;",
                    "Lcom/google/android/gms/wallet/LineItem",
                    "Lcom/google/android/gms/wallet/PaymentDataRequest$Builder;->addAllowedPaymentMethod"]):
                if "setTotalPrice" in ref["api"]:
                    found.add("totalPrice")
                elif "LineItem" in ref["api"]:
                    found.add("displayItems")
                elif "addAllowedPaymentMethod" in ref["api"]:
                    found.add("allowedPaymentMethods")
                else:
                    found.add("transactionInfo")
            built_here = bool(found & {"transactionInfo", "totalPriceStatus", "totalPrice"})
            # 缺金額 / 交易方式 -> 交易前一定無法告知; 缺商品名稱 -> 可能已顯示在 App 自己的結帳頁 (MAS 備註: 交易前通知即可)
            missing = [name for key, name in (("totalPrice", "amount (totalPrice)"),
                                              ("allowedPaymentMethods", "payment method (allowedPaymentMethods)"))
                       if key not in found]
            if not built_here:
                problem, confidence = ("payment request content not found in app code or resources "
                                       "(may be built elsewhere, e.g. by the server)"), "review"
            elif missing:
                problem, confidence = "Google Pay request has no " + ", ".join(missing), "high"
            elif "displayItems" not in found:
                problem, confidence = ("Google Pay request has no item name (displayItems); "
                                       "check whether the app shows it before paying"), "review"
            else:
                problem, confidence = None, "high"
            channels.append({"type": "google_pay", "where": gpay[0]["class"],
                             "evidence": {"calls": gpay[:5], "request_fields": sorted(found)},
                             "problem": problem, "confidence": confidence})

        # 2b. Samsung Pay (App 內付款): 跟 Google Pay 一樣由 App 組付款畫面 (CustomSheet), 金額要自己放進 AmountBoxControl
        #     沒有金額 -> 付款畫面不會顯示金額; 交易方式是使用者在 Samsung Pay 畫面選的卡, 一定會顯示
        spay = strip_instructions(find_app_references(dx, own, [
            "Lcom/samsung/android/sdk/samsungpay/v2/payment/PaymentManager;->startInAppPayWithCustomSheet"]))
        if spay:
            refs = strip_instructions(find_app_references(dx, own, [
                "Lcom/samsung/android/sdk/samsungpay/v2/payment/sheet/CustomSheet;-><init>",
                "Lcom/samsung/android/sdk/samsungpay/v2/payment/sheet/AmountBoxControl;-><init>",
                "Lcom/samsung/android/sdk/samsungpay/v2/payment/sheet/AmountBoxControl;->setAmountTotal",
                "Lcom/samsung/android/sdk/samsungpay/v2/payment/sheet/AmountBoxControl;->addItem"]))
            fields = {r["api"].rsplit("/", 1)[-1] for r in refs}   # CustomSheet;-><init>、AmountBoxControl;->addItem ...
            if "CustomSheet;-><init>" not in fields:
                problem, confidence = "Samsung Pay sheet content not found in app code", "review"
            elif not fields & {"AmountBoxControl;-><init>", "AmountBoxControl;->setAmountTotal"}:
                problem, confidence = "Samsung Pay sheet has no amount (AmountBoxControl)", "high"
            elif "AmountBoxControl;->addItem" not in fields:
                problem, confidence = ("Samsung Pay sheet has no item name (AmountBoxControl.addItem); "
                                       "check whether the app shows it before paying"), "review"
            else:
                problem, confidence = None, "high"
            channels.append({"type": "samsung_pay", "where": spay[0]["class"],
                             "evidence": {"calls": spay[:5], "sheet_fields": sorted(fields)},
                             "problem": problem, "confidence": confidence})

        # 3. 第三方支付 SDK: 結帳畫面由 SDK 顯示 (App 自己呼叫的 Samsung Pay 已在 2b 檢查)
        sdks = [s["library"] for s in find_class_prefixes(dx, PAYMENT_SDK_PREFIXES)
                if not (spay and s["library"] == "Samsung Pay")]
        for ref in find_app_references(dx, keep, [api for api, _ in PAYMENT_CALL_APIS]):
            name = next(n for api, n in PAYMENT_CALL_APIS if api == ref["api"])
            if name not in sdks:
                sdks.append(name)
        for name in sdks:
            channels.append({"type": "payment_sdk", "where": name, "evidence": {},
                             "problem": "third-party checkout screen not visible to static analysis",
                             "confidence": "review"})

        # 4. NFC 感應支付 (現場交易, MAS 基準 (2)): 設定要求解鎖 (requireDeviceUnlock) -> 使用者在現場解鎖授權, 符合;
        #    非付款類 (門禁、票證等 category="other") 不算交易; 設定讀不到或沒要求解鎖 -> 人工確認
        for service in a.get_services():
            actions = a.get_intent_filters("service", service).get("action", [])
            if "android.nfc.cardemulation.action.HOST_APDU_SERVICE" in actions:
                payment, unlock = hce_payment_info(a, service)
                if payment is False:
                    continue
                if payment and unlock:
                    channels.append({"type": "nfc_payment", "where": service, "evidence": {"require_device_unlock": True},
                                     "problem": None, "confidence": "high"})
                else:
                    channels.append({"type": "nfc_payment", "where": service,
                                     "evidence": {"require_device_unlock": False if payment else None},
                                     "problem": "contactless payment without requireDeviceUnlock, user confirmation not verifiable"
                                                if payment else "contactless payment, user confirmation not verifiable",
                                     "confidence": "review"})

        # 5. 網頁金流: App 程式碼或字串資源有付款網址
        def gateway(s):
            s = s or ""
            return next((n for url, n in PAYMENT_GATEWAY_URLS if url in s), None)
        gateways = {}
        for hit in find_app_const_strings(dx, gateway, keep):
            gateways.setdefault(hit["indicator"], hit["class"])
        for name, where in sorted(gateways.items()):
            channels.append({"type": "web_checkout", "where": "%s (%s)" % (name, where), "evidence": {},
                             "problem": "web checkout page, notice content not visible to static analysis",
                             "confidence": "review"})

        # 6. 自建刷卡畫面: 資源裡有信用卡安全碼 (CVV) 欄位
        card = find_card_form(a)
        if card:
            channels.append({"type": "card_form", "where": ", ".join(card), "evidence": {"resources": card},
                             "problem": "credit card input screen, notice content not visible to static analysis",
                             "confidence": "review"})

        # 6b. 跳到電子支付 App 付款 (街口、全支付、LINE Pay 等): 付款畫面在錢包 App, 看不到
        for name, where in sorted(wallet_app_targets(a, dx, keep).items()):
            channels.append({"type": "wallet_app", "where": "%s (%s)" % (name, where), "evidence": {},
                             "problem": "payment in e-wallet app, notice content not visible to static analysis",
                             "confidence": "review"})

        # 6c. 交易專用的介面文字 (付款、轉帳、點數兌換、儲值、購票、證券下單)
        text_hits = find_transaction_text(a)
        if text_hits:
            channels.append({"type": "transaction_text", "where": ", ".join("%s: %s" % (n, w) for n, w in text_hits),
                             "evidence": {"strings": [n for n, _ in text_hits]},
                             "problem": "transaction screen text found, notice content not visible to static analysis",
                             "confidence": "review"})

        # 7. 自建交易畫面 (Activity 名稱); 有內購時也要看, 但呼叫內購的畫面本身略過
        billing_screens = {ref["class"].split("$")[0].rstrip(";") for ref in billing}
        package = a.get_package() or ""
        for activity in a.get_activities():
            full = resolve_activity_name(package, activity)
            if not keep("L" + full.replace(".", "/") + ";"):
                continue
            if "L" + full.replace(".", "/") in billing_screens:
                continue
            simple = full.rsplit(".", 1)[-1]
            words = {w.lower() for w in re.findall(r'[A-Z]?[a-z]+|[A-Z]+(?![a-z])', simple)}
            lower = simple.lower()
            hit = (words & TRANSACTION_SCREEN_WORDS) or {w for w in ("checkout", "topup", "recharge") if w in lower}
            if hit:
                channels.append({"type": "custom_flow", "where": full, "evidence": {"words": sorted(hit)},
                                 "problem": "custom transaction screen, notice content not visible to static analysis",
                                 "confidence": "review"})

        # 8. 還是沒有: 金融 App 的交易畫面可能看不到, 交給人工
        if not channels:
            try:
                label = a.get_app_name() or ""
            except Exception:
                label = ""
            names = ((a.get_package() or "") + " " + label).lower()
            hit = sorted({w for w in FINANCE_APP_WORDS if w in names})
            if hit:
                channels.append({"type": "finance_app", "where": (a.get_package() or "") + (" (%s)" % label if label else ""),
                                 "evidence": {"words": hit},
                                 "problem": "financial app, transaction screens not found by static analysis",
                                 "confidence": "review"})
        return channels

    # ---- 敏感資料儲存 ----

    # 寫入裝置的 API: (API 片段, 儲存位置); SharedPreferences / ContentValues 第 1 個參數是 key, 第 2 個是值
    # 使用: lab_086, lab_087 (透過 find_sensitive_storage)
    KEYED_STORE_APIS = [
        ("Landroid/content/SharedPreferences$Editor;->put", "SharedPreferences"),
        ("Landroid/content/ContentValues;->put(",           "SQLite"),
    ]
    # 值寫進檔案 / DataStore / SQL 的 API (任一參數是敏感資料就算)
    VALUE_STORE_APIS = [
        ("Landroidx/datastore/preferences/core/MutablePreferences;->set(", "DataStore"),
        ("Landroid/database/sqlite/SQLiteDatabase;->execSQL(",              "SQLite"),
        ("Ljava/nio/file/Files;->write",                                    "File"),
        ("Lkotlin/io/FilesKt",                                              "File"),   # File.writeText / writeBytes / appendText
    ]
    # 寫串流的 API; 同一個 method 有開檔 (FILE_OPEN_APIS) 才算寫檔, 否則可能是網路串流
    STREAM_WRITE_APIS = ("Ljava/io/OutputStream;->write(", "Ljava/io/FileOutputStream;->write(",
                         "Ljava/io/Writer;->write(", "Ljava/io/Writer;->append(", "Ljava/io/FileWriter;->write(",
                         "Ljava/io/OutputStreamWriter;->write(", "Ljava/io/BufferedWriter;->write(",
                         "Ljava/io/PrintWriter;->print", "Ljava/io/PrintWriter;->write(")
    FILE_OPEN_APIS = ("Ljava/io/FileOutputStream;-><init>(", "Ljava/io/FileWriter;-><init>(",
                      "->openFileOutput(", "Ljava/io/RandomAccessFile;-><init>(")
    # 寫到其他 App / 系統的 provider (相簿、通訊錄), 不是 App 自己儲存
    # 使用: lab_086, lab_087 (透過 find_sensitive_storage)
    RESOLVER_WRITE_APIS = ("Landroid/content/ContentResolver;->insert(", "Landroid/content/ContentResolver;->update(",
                           "Landroid/content/ContentResolver;->bulkInsert(", "Landroid/content/ContentResolver;->applyBatch(")
    # DataStore 建 key 的函式; boolean / int 的 key 不會是敏感資料內容
    DATASTORE_KEY_FUNCS = ("->stringKey(", "->stringSetKey(", "->longKey(", "->floatKey(", "->doubleKey(")

    # 儲存用的敏感 key / 欄位名稱 (比 SENSITIVE_KEYWORD_RE 嚴: location、account、contact 常是路徑或內部 ID, 不算)
    # 使用: lab_086, lab_087 (透過 storage_key_sensitive)
    STORAGE_KEYWORD_RE = re.compile(
        r"(?<![a-z])(password|passwd|passcode|pwd|pin_?code|otp|secret|credentials?|cookies?|"
        r"(access|refresh|auth|id|session|bearer|login|api|user)?_?token|session_?id|api_?key|access_?key|private_?key|"
        r"phone(_?number)?|mobile(_?number)?|msisdn|e_?mails?(_?address)?|birthday|birth_?date|"
        r"id_?card|id_?number|national_id|ssn|card_?(number|no)|credit_card|cvv|iban|account_?(number|no|name)|"
        r"imei|imsi|iccid|meid|android_?id|advertising_?id|latitude|longitude|lat|lng|"
        r"user_?name|login_?(id|name)|real_?name|full_?name)(?![a-z])"
        r"|密碼|帳號|身分證|電話|手機|信用卡|生日")
    # 存放 MAS 3.4 所列個人隱私資料的資料表名稱 (即時通訊訊息、簡訊、通話記錄、備忘錄、筆記、通訊錄、行事曆)
    # 使用: lab_086, lab_087 (透過 sql_sensitive_columns)
    CONTENT_TABLE_RE = re.compile(
        r"(?<![a-z])(messages?|sms|mms|chats?|conversations?|call_?logs?|memos?|notes?|contacts?|calendars?|attendees?)(?![a-z])")
    # 不會改寫第一個暫存器的指令 (常數、呼叫、判斷、寫入欄位 / 陣列、return 等)
    # 使用: lab_086, lab_087 (透過 find_sensitive_storage)
    REG_KEEP_PREFIXES = ("const", "invoke", "if-", "iput", "sput", "aput", "return", "throw", "monitor", "check-cast",
                         "goto", "fill-array", "packed-switch", "sparse-switch", "nop", "filled-new-array")
    # 靜態看不出內容的資料來源: 輸入框的文字 (筆記、訊息)、加密後的資料 (金鑰、密碼庫); 寫進裝置時列為待確認
    # 使用: lab_086, lab_087 (透過 find_sensitive_storage)
    UNKNOWN_CONTENT_SOURCES = ("text typed by the user", "encrypted data", "serialized object")
    # 把物件轉成字串的 API (Gson、Moshi、kotlinx.serialization、JSONObject); 存起來時看不出物件裡有哪些欄位
    # 使用: lab_086, lab_087 (透過 find_sensitive_storage)
    SERIALIZE_APIS = ("Lcom/google/gson/Gson;->toJson(", "Lcom/squareup/moshi/JsonAdapter;->toJson(",
                      "Lkotlinx/serialization/json/Json;->encodeToString(", "Lorg/json/JSONObject;->toString(",
                      "Lorg/json/JSONArray;->toString(")
    # 寫入內容看不出來時列出的 API (SharedPreferences / DataStore 的 key 名稱看得出用途, 不列)
    # 使用: lab_086, lab_087 (透過 find_sensitive_storage)
    UNIDENTIFIED_WRITE_APIS = ("Ljava/nio/file/Files;->write", "Lkotlin/io/FilesKt", "Landroid/database/sqlite/SQLiteDatabase;->execSQL(")
    UNIDENTIFIED_REASON = "content cannot be identified statically; check whether it is sensitive"
    # 函式庫的資料表 (混淆後 class 名稱看不出是函式庫, 用表名排除): WorkManager、ExoPlayer
    # 使用: lab_086, lab_087 (透過 sql_text_table)
    LIB_TABLE_NAMES = {"WorkSpec", "WorkTag", "WorkName", "Dependency", "SystemIdInfo", "WorkProgress", "Preference",
                       "ExoPlayerVersions"}
    # 資料表是 SDK 自己的佇列 / 快取, 不是使用者資料 (例 Firebase Analytics 的 messages 表是待上傳事件)
    # 使用: lab_086, lab_087 (透過 find_sensitive_storage)
    SDK_TABLE_PREFIXES = ("Lcom/google/android/gms/", "Lcom/google/firebase/", "Lcom/google/android/datatransport/",
                          "Landroidx/work/", "Landroidx/media3/", "Lcom/google/android/exoplayer2/")
    # 名稱是描述資料的設定 (時間、次數、開關、推播 token), 不是資料本身
    STORAGE_KEY_EXCLUDE_RE = re.compile(
        r"(?<![a-z])(time|timestamp|date|count|counter|freq|frequency|reminder|position|enabled?|asked|shown|flag|"
        r"version|permission|mode|type|status|interval|updated?|setting|prompt|hint|label|length|format|required|"
        r"visible|verified|policy|size|expires?|expiry|push|fcm|gcm|firebase|notification|registration|apns|"
        r"author|developer|support|maintainer)s?(?![a-z])")

    # 密碼輸入框: layout 的 inputType (textPassword 0x81 / textWebPassword 0xe1 / numberPassword 0x12) 或 android:password
    # 使用: lab_086, lab_087 (透過 password_view_names)
    PASSWORD_INPUT_TYPES = (0x81, 0xe1, 0x12)
    # 名稱像密碼欄位的 View (欄位名或 R.id 名稱); 看不到 layout 時用
    PASSWORD_VIEW_RE = re.compile(r"(password|passwd|pwd|passcode|pin_?code|otp|密碼)")

    # 輸入框 / 勾選框的類別名稱結尾
    # 使用: lab_086, lab_087 (透過 find_sensitive_storage, store_switch_reads)
    TEXT_INPUT_TYPES = ("EditText;", "TextInputEditText;", "TextInputLayout;", "AutoCompleteTextView;")
    CHECKABLE_TYPES = ("CheckBox;", "Switch;", "SwitchCompat;", "SwitchMaterial;", "MaterialSwitch;",
                       "CompoundButton;", "ToggleButton;", "MaterialCheckBox;")

    # 同意 / 隱私相關的 key、畫面、字串
    # 使用: lab_086 (透過 find_storage_consent)
    # 只有 privacy / policy 不算 (例 reblogPrivacy 是貼文公開範圍), 要像 privacy_policy、privacy_agreed
    CONSENT_KEY_RE = re.compile(
        r"(?<![a-z])(consent(ed|s)?|agree(d|ment|s)?|eula|gdpr|"
        # accept / terms 單獨出現常是別的意思 (acceptHeader、autoAccept、terms_shown), 要兩個一起
        r"(accept(ed)?|confirm(ed)?|read|ack(nowledged)?)_([a-z]+_)?(terms|tos|policy|privacy|eula|disclaimer|license|legal|cookies?)|"
        r"(terms|tos|policy|privacy|eula|disclaimer|license|legal|cookies?)_([a-z]+_)?(accept(ed)?|confirm(ed)?|read|ack(nowledged)?)|"
        r"privacy_?(policy|notice|statement|agree|agreed|accepted|confirmed?|read))(?![a-z])"
        r"|同意|條款|隱私權?(政策|聲明)")
    # 畫面名稱: 同意畫面 (算取得同意) / 聲明畫面 (只顯示條款, 不確定有取得同意)
    CONSENT_SCREEN_WORDS = {"consent", "agreement", "agree", "eula"}
    NOTICE_SCREEN_WORDS = {"privacy", "terms", "policy", "disclaimer"}
    PRIVACY_TEXT_RE = re.compile(r"privacy|隱私|個資|個人資料", re.I)
    # 函式庫自帶的字串資源前綴, 不算 App 自己的聲明
    LIB_RES_PREFIXES = ("abc_", "mtrl_", "material_", "common_", "com_facebook_", "fui_", "m3_", "exo_", "androidx_",
                        "preference_", "fab_", "bottom_sheet_", "appbar_", "search_menu_", "status_bar_", "gms_", "fcm_")
    # 算「取得同意」的機制 (其他如 privacy_text、notice_screen 只算告知)
    # 使用: lab_086 (透過 storage_consent_result)
    CONSENT_TYPES = ("consent_check", "consent_sdk", "consent_screen")
    # 同意管理 SDK; App 自己有呼叫才算
    CONSENT_SDK_PREFIXES = [
        ("Lcom/google/android/ump/", "Google User Messaging Platform"),
        ("Lcom/onetrust/",           "OneTrust"),
        ("Lio/didomi/",              "Didomi"),
        ("Lcom/usercentrics/",       "Usercentrics"),
        ("Lcom/sourcepoint/",        "Sourcepoint"),
    ]

    # 拒絕儲存的開關 key (記住帳號、儲存密碼、自動登入、生物辨識登入、App 密碼鎖)
    # 使用: lab_087
    STORE_SWITCH_RE = re.compile(
        r"(?<![a-z])(auto_?login|auto_?fill|(stay|keep)_?(logged|signed)|quick_?login|biometrics?|fingerprint|"
        r"protection|app_?lock|pin_?lock|"
        # remember / save 等要接帳密類的字 (keep_screen_on、save_images、auto_save 不算)
        r"(remember|save|store|keep|persist)_([a-z]+_)?(me|password|passwd|pwd|pass|passcode|pin|account|user|"
        r"username|user_?name|login|credentials?|id|token|session|card|email|phone|location))(?![a-z])"
        r"|(?<![a-z])(?<!auto_)(remember|save)$|記住|記憶|儲存|保存|自動登入|快速登入")

    # 儲存的資料 -> Google Play 資料安全性類別 (比對 storage 的 data / key); 密碼、token 等沒有對應類別
    # 使用: lab_086 (透過 storage_store_unconfirmed)
    STORAGE_PLAY_CATEGORIES = [
        (r"(?<![a-z])(lat|lng|latitude|longitude|location)(?![a-z])",                          "location"),
        (r"(?<![a-z])(imei|imsi|iccid|meid|android_?id|advertising_?id|device)(?![a-z])",       "device or other ids"),
        (r"(?<![a-z])(card_?(number|no)|credit_card|cvv|iban|account_?(number|no))(?![a-z])",   "financial info"),
        (r"(?<![a-z])(messages?|sms|mms|chats?|conversations?)(?![a-z])",                       "messages"),
        (r"(?<![a-z])(contacts?|call_?logs?)(?![a-z])",                                         "contacts"),
        (r"(?<![a-z])(calendars?|attendees?)(?![a-z])",                                         "calendar"),
        (r"(?<![a-z])(phone(_?numbers?)?|mobile(_?number)?|msisdn|e_?mails?(_?address)?|birthday|birth_?date|"
         r"id_?card|id_?number|national_id|ssn|user_?name|login_?(id|name)|real_?name|full_?name|account_?name)(?![a-z])",
         "personal info"),
    ]
    # 自己套件的 class 少於這個數又找不到儲存 -> 程式碼看不到 (加殼), 無法判定
    # 使用: lab_086, lab_087 (透過 storage_consent_result)
    STORAGE_MIN_CLASSES = 10

    def storage_key_sensitive(key):
        """key / 欄位名稱是敏感資料 -> 回傳命中的字, 否則 None (時間、次數、開關、推播 token 等排除)
        使用: lab_086, lab_087 (透過 find_sensitive_storage)"""
        if not isinstance(key, str) or not key:
            return None
        words = split_words(key)
        if STORAGE_KEY_EXCLUDE_RE.search(words):
            return None
        for m in STORAGE_KEYWORD_RE.finditer(words):
            # 分頁 / 同步用的 token (next_page_token、syncToken) 不是使用者資料
            if m.group(0).endswith("token") and re.search(r"(page|paging|pagination|sync|continuation|cursor)_?$",
                                                         words[:m.start()]):
                continue
            return m.group(0)
        return None

    def resource_name(arsc, rid):
        """資源編號 -> 名稱 (例 0x7f0a0012 -> 'et_password'), 查不到回傳 None
        使用: lab_086, lab_087 (透過 find_sensitive_storage, store_switch_reads, password_view_names)"""
        try:
            name = arsc.get_resource_xml_name(rid) if arsc is not None else None
        except Exception:
            return None
        return name.split("/", 1)[-1] if name else None

    def password_view_names(a):
        """layout 裡密碼輸入框的 id 名稱 (inputType 是密碼或 android:password="true")
        使用: lab_086, lab_087 (透過 find_sensitive_storage)"""
        try:
            from androguard.core.axml import AXMLPrinter
        except ImportError:
            from androguard.core.bytecodes.axml import AXMLPrinter
        import xml.etree.ElementTree as ET
        names = set()
        for f in a.get_files():
            if not (f.startswith("res/layout") and f.endswith(".xml")):
                continue
            try:
                root = ET.fromstring(AXMLPrinter(a.get_file(f)).get_buff())
            except Exception:
                continue
            for el in root.iter():
                vid = el.get(ANDROID_NS + "id") or ""
                if not vid:
                    continue
                kind = (el.get(ANDROID_NS + "inputType") or "").lower()
                try:
                    num = int(kind, 0) if kind.startswith("0x") or kind.isdigit() else None
                except ValueError:
                    num = None
                if "password" in kind or (num is not None and (num & 0xfff) in PASSWORD_INPUT_TYPES) \
                        or el.get(ANDROID_NS + "password") == "true":
                    names.add(vid.split("/", 1)[-1])
        return names

    def sql_sensitive_columns(sql):
        """CREATE TABLE 字串裡的敏感資料 -> [(表名, 欄位或 None, 說明)]
        1. 欄位名稱是敏感資料 (password、phone 等); 2. 表名是訊息、筆記、通訊錄、行事曆 (CONTENT_TABLE_RE) 且有文字欄位
        使用: lab_086, lab_087 (透過 find_sensitive_storage)"""
        m = re.match(r"\s*create\s+(?:virtual\s+)?table\s+(?:if\s+not\s+exists\s+)?[`\"\[]?([\w.]+)[`\"\]]?\s*\((.*)\)",
                     sql or "", re.I | re.S)
        if not m:
            return []
        cols, text_cols = [], 0
        for part in m.group(2).split(","):
            words = part.strip().split()
            if not words or words[0].upper() in ("PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT"):
                continue
            col = words[0].strip("`\"[]")
            if storage_key_sensitive(col):
                cols.append((m.group(1), col, "column '%s'" % col))
            elif len(words) > 1 and words[1].strip("`\"[]").upper().startswith(("TEXT", "VARCHAR", "BLOB")) \
                    and not STORAGE_KEY_EXCLUDE_RE.search(split_words(col)) \
                    and not re.search(r"(?<![a-z])(id|uid|url|uri|path|key|hash|color|icon)$", split_words(col)):
                text_cols += 1
        table = re.sub(r"^_?new_|_?entity$", "", split_words(m.group(1)))
        hit = CONTENT_TABLE_RE.search(table)
        if hit and text_cols and not cols:
            cols.append((m.group(1), None, "table '%s' (%s)" % (m.group(1), hit.group(0))))
        return cols

    def method_param_regs(ma):
        """method 參數對應的暫存器: 第 i 個參數 (不含 this) -> 'vN'; wide (long / double) 佔兩個
        使用: lab_086, lab_087 (透過 find_sensitive_storage)"""
        try:
            code = ma.get_method().get_code()
            first = code.get_registers_size() - code.get_ins_size()
        except Exception:
            return []
        params = re.findall(r'\[*(?:L[^;]+;|[ZBSCIJFD])', str(ma.descriptor).split(")")[0].replace(" ", ""))
        reg = first + (0 if "static" in (ma.get_method().get_access_flags_string() or "") else 1)
        regs = []
        for p in params:
            regs.append("v%d" % reg)
            reg += 2 if p in ("J", "D") else 1
        return regs

    def find_sensitive_storage(a, dx, keep):
        """找 App 把敏感資料寫進裝置 (SharedPreferences、DataStore、SQLite、檔案) 的地方
        敏感資料: 1. key / 欄位名稱是敏感資料 (password、token、phone 等); 2. 值來自敏感資料 API (定位、通訊錄、裝置 ID)
                  或密碼輸入框, 在 method 內追蹤暫存器, 傳給 App 自己的 method 再追 2 層
        回傳 [{"store", "where", "key", "data", "confidence" (high / review), "reason", "method" (寫入的 method 或 None)}]
          review = 名稱像敏感資料但存的是整數 (可能是 ID / 次數), 或存的是看不出內容的資料 (UNKNOWN_CONTENT_SOURCES)
        使用: lab_086, lab_087 (透過 storage_consent_result)"""
        api_names = sensitive_api_names()
        try:
            arsc = a.get_android_resources()
        except Exception:
            arsc = None
        pw_ids = password_view_names(a)
        found, seen, done = [], set(), {}
        crypto = crypto_wrapper_methods(dx, keep)
        generic_tables = set()

        def add(store, where, key, data, ma, confidence="high", reason=""):
            k = (store, where, key)
            if k in seen:
                return
            if confidence == "high" and isinstance(data, str) and data.startswith(UNKNOWN_CONTENT_SOURCES):
                # 使用者打的字 / 加密資料: key 是敏感名稱就確定, 否則看不出內容, 交給人工
                word = storage_key_sensitive(key)
                if word:
                    data = "key '%s' (%s)" % (word, data)
                else:
                    confidence, reason = "review", "content cannot be identified statically; check whether it is sensitive"
            seen.add(k)
            found.append({"store": store, "where": where, "key": key, "data": data, "confidence": confidence,
                          "reason": reason, "method": ma})

        def where_of(ma):
            return "%s.%s" % (ma.class_name[1:-1].replace("/", "."), ma.name)

        def scan(ma, tainted, depth):
            # tainted: {暫存器: 資料來源說明}
            sig = (ma.class_name, ma.name, str(ma.descriptor), tuple(sorted(tainted)))
            if sig in done or len(done) > 20000:
                return
            done[sig] = True
            try:
                instructions = list(ma.get_method().get_instructions())
            except Exception:
                return
            outs = [ins.get_output() for ins in instructions]
            # 有開檔才算寫檔; 寫到其他 App 的 provider 不算
            opens_file = any(api in o for o in outs for api in FILE_OPEN_APIS)
            resolver = any(api in o for o in outs for api in RESOLVER_WRITE_APIS)
            taint, consts, pending, pending_const, pending_sb, sb_consts = dict(tainted), {}, None, None, None, {}
            for ins, out in zip(instructions, outs):
                name = ins.get_name()
                regs = ins_registers(ins)
                # 暫存器被改寫 -> 原本的常數 (key 名稱) 失效, 避免把舊的字串當成 key (move 會帶著常數)
                if regs and not name.startswith(REG_KEEP_PREFIXES):
                    if name.startswith("move") and not name.startswith("move-result") and len(regs) > 1 \
                            and regs[1] in consts:
                        consts[regs[0]] = consts[regs[1]]
                    else:
                        consts.pop(regs[0], None)
                    sb_consts.pop(regs[0], None)
                if name.startswith("const-string") and regs:
                    consts[regs[0]] = ins.get_string()
                    taint.pop(regs[0], None)
                    for table, col, data in sql_sensitive_columns(ins.get_string()):
                        add("SQLite", where_of(ma), "%s.%s" % (table, col) if col else table, data, None)
                    generic = sql_text_table(ins.get_string())
                    if generic and generic[0] not in generic_tables:   # onCreate / onUpgrade 同一張表只列一次
                        generic_tables.add(generic[0])
                        add("SQLite", where_of(ma), generic[0], generic[1], None, "review", UNIDENTIFIED_REASON)
                elif name.startswith("const") and regs:
                    try:
                        consts[regs[0]] = ins.get_literals()[0]
                    except Exception:
                        consts.pop(regs[0], None)
                    taint.pop(regs[0], None)
                elif name.startswith("iget-object") and regs:
                    # 密碼輸入框的欄位 (含 ViewBinding 的 binding.etPassword)
                    field = re.split(r"[ :]", out.rsplit("->", 1)[-1].strip(), 1)
                    fname, ftype = field[0], field[-1]
                    taint.pop(regs[0], None)
                    if ftype.endswith(TEXT_INPUT_TYPES) and PASSWORD_VIEW_RE.search(split_words(fname)):
                        taint[regs[0]] = "password field %s" % fname
                    elif len(regs) > 1 and regs[1] in taint:
                        taint[regs[0]] = taint[regs[1]]
                elif name.startswith("invoke"):
                    pending = None
                    args = [r for _, r in invoke_args(name, out, regs)]
                    this = regs[0] if regs and "static" not in name else None
                    # 字串串接的 key ("token_" + id): StringBuilder 記住開頭的常數, toString() 的結果當作 key
                    pending_const = pending_sb = None
                    # 只認開頭是常數的 (前面接變數的 prefix + ".key" 看不出 key)
                    if "Ljava/lang/StringBuilder;" in out.split("->", 1)[0] and this:
                        first = consts.get(args[0]) if args and isinstance(consts.get(args[0]), str) else False
                        if "-><init>()V" in out:
                            sb_consts[this] = ""
                        elif "-><init>(Ljava/lang/String;)" in out:
                            sb_consts[this] = first
                        elif "->append(" in out and this in sb_consts:
                            if sb_consts[this] == "":
                                sb_consts[this] = first
                            pending_sb = sb_consts[this]   # append 回傳同一個 StringBuilder
                        elif "->toString()" in out and sb_consts.get(this):
                            pending_const = sb_consts[this]
                    elif "Ljava/lang/String;->concat(" in out and this and isinstance(consts.get(this), str):
                        pending_const = consts[this]
                    hit = [taint[r] for r in regs if r in taint]
                    api_hit = next((n for api, n in api_names if api in out), None)
                    if api_hit:
                        pending = "reads %s" % api_hit
                    elif "Landroid/provider/Settings$Secure;->getString(" in out and len(args) > 1 \
                            and consts.get(args[1]) == "android_id":
                        pending = "reads Android ID"
                    elif "->findViewById(I)" in out and args and isinstance(consts.get(args[0]), int):
                        vname = resource_name(arsc, consts[args[0]])
                        if vname and (vname in pw_ids or PASSWORD_VIEW_RE.search(vname)):
                            pending = "password field %s" % vname
                    elif not hit and "->getText()Landroid/text/Editable;" in out:
                        pending = UNKNOWN_CONTENT_SOURCES[0]
                    elif not hit and "Ljavax/crypto/Cipher;->doFinal(" in out:
                        pending = UNKNOWN_CONTENT_SOURCES[1]
                    elif not hit and invoke_target(out) in crypto:
                        # App 自己的加解密函式 (AESUtil.encrypt) 回傳的資料
                        pending = "%s from %s" % (UNKNOWN_CONTENT_SOURCES[1], invoke_target(out).split("(", 1)[0])
                    elif not hit and any(api in out for api in SERIALIZE_APIS):
                        pending = UNKNOWN_CONTENT_SOURCES[2]
                    elif any(api in out for api, _ in KEYED_STORE_APIS):
                        store = next(s for api, s in KEYED_STORE_APIS if api in out)
                        if store == "SQLite" and resolver:
                            continue
                        m = re.search(r'->(\w+)\(([^)]*)\)', out)
                        api, params = (m.group(1), m.group(2)) if m else ("", "")
                        if api == "putBoolean" or len(args) < 2:
                            continue
                        key = consts.get(args[0])
                        value_type = re.findall(r'\[*(?:L[^;]+;|[ZBSCIJFD])', params.replace(" ", ""))
                        value_type = value_type[1] if len(value_type) > 1 else ""
                        if value_type in ("Z", "Ljava/lang/Boolean;"):
                            continue
                        if args[1] in taint:
                            add(store, where_of(ma), key, taint[args[1]], ma)
                        else:
                            word = storage_key_sensitive(key)
                            if word and value_type in ("I", "J", "Ljava/lang/Integer;", "Ljava/lang/Long;"):
                                add(store, where_of(ma), key, "key '%s'" % word, ma, "review",
                                    "key looks sensitive but the value is a number")
                            elif word:
                                add(store, where_of(ma), key, "key '%s'" % word, ma)
                        continue
                    elif any(f in out for f in DATASTORE_KEY_FUNCS) and args \
                            and storage_key_sensitive(consts.get(args[0])):
                        add("DataStore", where_of(ma), consts.get(args[0]),
                            "key '%s'" % storage_key_sensitive(consts.get(args[0])), None)
                    elif "Lorg/json/JSONObject;->put(" in out and this and len(args) > 1 \
                            and storage_key_sensitive(consts.get(args[0])):
                        # json.put("password", v): 之後整個 JSON 物件都帶敏感資料 (存進 SharedPreferences / 檔案時才算儲存)
                        taint[this] = pending = "json field '%s'" % storage_key_sensitive(consts.get(args[0]))
                        continue
                    elif hit and (any(api in out for api, _ in VALUE_STORE_APIS)
                                  or (opens_file and any(api in out for api in STREAM_WRITE_APIS))):
                        store = next((s for api, s in VALUE_STORE_APIS if api in out), "File")
                        add(store, where_of(ma), None, hit[0], ma)
                        continue
                    elif depth == 0 and args and not any(r in consts for r in args) \
                            and (any(api in out for api in UNIDENTIFIED_WRITE_APIS)
                                 or (opens_file and any(api in out for api in STREAM_WRITE_APIS))):
                        # 寫檔 / SQL 的內容不是常數, 也追不到來源: 看不出存了什麼
                        store = "SQLite" if "SQLiteDatabase" in out else "File"
                        add(store, where_of(ma), None, "content not identified", ma, "review", UNIDENTIFIED_REASON)
                        continue
                    elif hit and depth < 2:
                        # 敏感資料傳給 App 自己的 method -> 進去追 (例 saveToken(token))
                        callee_cls = out.split("->", 1)[0].split()[-1] if "->" in out else ""
                        if keep(callee_cls) and callee_cls in dx.classes:
                            m = re.search(r'->([^(]+)(\([^)]*\)\S+)$', out)
                            for callee in dx.classes[callee_cls].get_methods() if m else []:
                                if callee.name != m.group(1) or str(callee.descriptor).replace(" ", "") \
                                        != m.group(2).replace(" ", "") or callee.is_external():
                                    continue
                                preg = method_param_regs(callee)
                                sub = {preg[i]: taint[r] for i, r in enumerate(args) if r in taint and i < len(preg)}
                                if sub:
                                    scan(callee, sub, depth + 1)
                    if hit:
                        pending = pending or hit[0]
                        if this and not keep(out.split("->", 1)[0].split()[-1]):
                            taint[this] = hit[0]   # 系統 / 函式庫物件: sb.append(pw)、json.put(k, pw) 之後物件本身也帶資料
                elif name.startswith("move-result") and regs:
                    if pending:
                        taint[regs[0]] = pending
                    else:
                        taint.pop(regs[0], None)
                    if pending_const:
                        consts[regs[0]] = pending_const
                    if pending_sb is not None:
                        sb_consts[regs[0]] = pending_sb
                    pending = pending_const = pending_sb = None
                elif name.startswith(("if-", "goto", "return", "iput", "sput", "aput", "monitor", "throw",
                                      "packed-switch", "sparse-switch", "fill-array", "nop")):
                    continue
                elif len(regs) >= 2:
                    # move / 型別轉換 / 運算: 來源有資料 -> 結果也有 (check-cast 不改變暫存器)
                    src = next((taint[r] for r in regs[1:] if r in taint), None)
                    if src:
                        taint[regs[0]] = src
                    else:
                        taint.pop(regs[0], None)
                elif regs and not name.startswith("check-cast"):
                    taint.pop(regs[0], None)

        for cls, ca in dx.classes.items():
            if not keep(cls):
                continue
            for ma in ca.get_methods():
                if not ma.is_external():
                    scan(ma, {}, 0)
        # 資料表定義不分 App / 函式庫都算儲存在裝置上 (R8 會把 App 的 class 併進函式庫套件, 例 k9 的 messages 表在 okhttp3 下)
        for s in dx.find_strings(r"(?i)^\s*create\s+(virtual\s+)?table"):
            for ca, ma in s.get_xref_from():
                if keep(ca.name) or ca.name.startswith(SDK_TABLE_PREFIXES):
                    continue
                for table, col, data in sql_sensitive_columns(s.get_value()):
                    add("SQLite", where_of(ma), "%s.%s" % (table, col) if col else table, data, None)
        return found

    def find_storage_consent(a, dx, keep):
        """找 App 的同意 / 聲明機制, 回傳 [{"type", "where", "evidence"}]
        consent_check = 程式讀寫同意狀態 (key 含 consent / agree / privacy 等); consent_screen = 同意畫面;
        notice_screen = 隱私權 / 條款畫面 (只算告知);
        consent_sdk = App 有呼叫同意管理 SDK; privacy_text = 程式碼或字串資源有隱私權政策 (連結或文字)
        使用: lab_086 (透過 storage_consent_result)"""
        found = []
        pref_apis = ("Landroid/content/SharedPreferences;->getBoolean(", "Landroid/content/SharedPreferences$Editor;->putBoolean(",
                     "Landroid/content/SharedPreferences;->getInt(", "Landroid/content/SharedPreferences$Editor;->putInt(",
                     "Landroid/content/SharedPreferences;->getString(", "Landroid/content/SharedPreferences$Editor;->putString(",
                     "->booleanKey(")
        checks, texts = {}, {}
        for cls, ca in dx.classes.items():
            if not keep(cls):
                continue
            for ma in ca.get_methods():
                if ma.is_external():
                    continue
                try:
                    instructions = list(ma.get_method().get_instructions())
                except Exception:
                    continue
                consts = {}
                where = "%s.%s" % (cls[1:-1].replace("/", "."), ma.name)
                for ins in instructions:
                    name = ins.get_name()
                    regs = ins_registers(ins)
                    if name.startswith("const-string") and regs:
                        value = ins.get_string()
                        consts[regs[0]] = value
                        # 連結, 或像句子的文字 (有空白或中文); privacy_policy_agreed 這種 key 不算
                        if PRIVACY_TEXT_RE.search(value or "") and len(value) < 300 \
                                and ("http" in value or (re.search(r"\s|[^\x00-\x7f]", value)
                                                         and re.search(r"polic|政策|聲明|notice", value, re.I))):
                            texts.setdefault(value[:80], where)
                    elif name.startswith("invoke") and any(api in ins.get_output() for api in pref_apis):
                        args = [r for _, r in invoke_args(name, ins.get_output(), regs)]
                        key = consts.get(args[0]) if args else None
                        if isinstance(key, str) and CONSENT_KEY_RE.search(split_words(key)):
                            checks.setdefault(key, where)
        for key, where in sorted(checks.items())[:5]:
            found.append({"type": "consent_check", "where": where, "evidence": "key '%s'" % key})

        package = a.get_package() or ""
        for activity in a.get_activities():
            full = resolve_activity_name(package, activity)
            if not keep("L" + full.replace(".", "/") + ";"):
                continue
            words = {w.lower() for w in re.findall(r'[A-Z]?[a-z]+|[A-Z]+(?![a-z])', full.rsplit(".", 1)[-1])}
            if words & CONSENT_SCREEN_WORDS:
                found.append({"type": "consent_screen", "where": full, "evidence": "activity name"})
            elif words & NOTICE_SCREEN_WORDS:
                found.append({"type": "notice_screen", "where": full, "evidence": "activity name"})

        for sdk in find_app_sdk_calls(dx, keep, CONSENT_SDK_PREFIXES):
            found.append({"type": "consent_sdk", "where": sdk["caller"], "evidence": sdk["library"]})

        for value, where in sorted(texts.items())[:3]:
            found.append({"type": "privacy_text", "where": where, "evidence": value})
        # 字串資源: 名稱或內容是隱私權政策 / 同意條款 (函式庫的資源排除)
        try:
            arsc = a.get_android_resources()
            strings = arsc.get_resolved_strings().get(package, {}).get("DEFAULT", {})
        except Exception:
            arsc, strings = None, {}
        hits = []
        for rid, value in strings.items():
            rname = resource_name(arsc, rid) or ""
            if rname.startswith(LIB_RES_PREFIXES):
                continue
            if re.search(r"privacy_?(policy|statement|notice)|consent|terms_of|user_agreement|隱私", rname, re.I) \
                    or re.search(r"privacy policy|隱私權政策|隱私權聲明|個資.{0,4}(告知|聲明)|同意.{0,10}(隱私|條款)", value or "", re.I):
                hits.append((rname, (value or "")[:60]))
        for rname, value in sorted(hits)[:3]:
            found.append({"type": "privacy_text", "where": "string/%s" % rname, "evidence": value})
        return found

    def store_switch_reads(ma, dx, cache):
        """lab_087 讀開關的函式 (給 path_evidence 用): switch_reads 之外, 再認畫面上的勾選框 isChecked()
        勾選框的 key 用欄位名稱 (cbRemember、binding.switchSave) 或 findViewById 的 R.id 名稱
        使用: lab_087 (透過 path_evidence)"""
        reads = switch_reads(ma, dx, cache)
        try:
            instructions = [] if ma.is_external() else list(ma.get_method().get_instructions())
        except Exception:
            return reads
        arsc = cache.get("_arsc")
        consts, views, values, pending, checks = {}, {}, {}, None, []
        for ins in instructions:
            name, out = ins.get_name(), ins.get_output()
            regs = ins_registers(ins)
            if name.startswith("const") and name != "const-class" and not name.startswith("const-string") and regs:
                try:
                    consts[regs[0]] = ins.get_literals()[0]
                except Exception:
                    consts.pop(regs[0], None)
                views.pop(regs[0], None)
                values.pop(regs[0], None)
            elif name.startswith("iget-object") and regs:
                field = re.split(r"[ :]", out.rsplit("->", 1)[-1].strip(), 1)
                views.pop(regs[0], None)
                values.pop(regs[0], None)
                if field[-1].endswith(CHECKABLE_TYPES):
                    views[regs[0]] = field[0]
            elif name.startswith("invoke"):
                for r in regs:
                    if r in values:
                        checks[values[r]]["passed"] = True
                pending = None
                args = [r for _, r in invoke_args(name, out, regs)]
                if "->findViewById(I)" in out and args and isinstance(consts.get(args[0]), int):
                    pending = ("view", resource_name(arsc, consts[args[0]]))
                elif "->isChecked()Z" in out and regs and regs[0] in views:
                    checks.append({"key": views[regs[0]], "branch": False, "passed": False})
                    pending = ("check", len(checks) - 1)
            elif name.startswith("move-result") and regs:
                views.pop(regs[0], None)
                values.pop(regs[0], None)
                if pending and pending[0] == "view" and pending[1]:
                    views[regs[0]] = pending[1]
                elif pending and pending[0] == "check":
                    values[regs[0]] = pending[1]
                pending = None
            elif name.startswith("check-cast"):
                continue
            elif name.startswith("if-"):
                for r in regs:
                    if r in values:
                        checks[values[r]]["branch"] = True
            elif name.startswith(("return", "iput", "sput", "aput")):
                if regs and regs[0] in values:
                    checks[values[regs[0]]]["passed"] = True
            elif len(regs) >= 2 and name.startswith("move") and (regs[1] in values or regs[1] in views):
                if regs[1] in values:
                    values[regs[0]] = values[regs[1]]
                else:
                    views[regs[0]] = views[regs[1]]
            elif regs:
                views.pop(regs[0], None)
                values.pop(regs[0], None)
        return reads + [{"key": c["key"], "default": None, "api": "CheckBox",
                         "use": "branch" if c["branch"] else ("passed" if c["passed"] else "unused")} for c in checks]

    # lab_086 / 087 分析同一個 APK 時共用結果; 只在 a、dx 是同一個物件時使用, 載入新 APK 時清掉
    # 使用: lab_086, lab_087 (透過 storage_consent_result), load_apk
    STORAGE_RESULT_CACHE = {}

    def storage_consent_result(a, dx):
        """lab_086 / 087 共用結果: 同一個 APK 只分析一次 (lab_087 不再重算), 回傳副本避免兩邊互相影響
        使用: lab_086, lab_087"""
        entry = STORAGE_RESULT_CACHE.get("entry")
        if not entry or entry[0] is not a or entry[1] is not dx:
            STORAGE_RESULT_CACHE["entry"] = entry = (a, dx, storage_consent_analyze(a, dx))
        return container_copy(entry[2])

    def container_copy(value):
        """複製 dict / list / tuple 的結構, 裡面的 androguard 物件 (method 等, 無法 deepcopy) 維持共用
        使用: lab_086, lab_087 (透過 storage_consent_result)"""
        if isinstance(value, dict):
            return {k: container_copy(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return type(value)(container_copy(v) for v in value)
        if isinstance(value, set):
            return set(value)
        return value

    def storage_consent_analyze(a, dx):
        """lab_086 / 087 共用: 敏感資料儲存 + 同意機制 + 4.1.2.3.1 判定
        回傳 {"storage": 確定的儲存, "review": 待確認的儲存, "consent": 同意機制, "own_classes",
              "verdict_086": WARNING (有儲存沒同意) / NOT_EVALUATED / PASS, "reason"}
        使用: lab_086, lab_087"""
        keep = app_class_filter(a)
        storage = find_sensitive_storage(a, dx, keep)
        high = [s for s in storage if s["confidence"] == "high"]
        review = [s for s in storage if s["confidence"] != "high"]
        prefixes = app_own_prefixes(a)
        own = sum(1 for c in dx.classes if c.startswith(prefixes)) if prefixes else 0
        consent = find_storage_consent(a, dx, keep) if storage else []
        if not storage:
            verdict = "NOT_EVALUATED" if own < STORAGE_MIN_CLASSES else "PASS"
            reason = "app code not visible (packed?)" if verdict == "NOT_EVALUATED" else "no sensitive data storage found"
        elif any(c["type"] in CONSENT_TYPES for c in consent):
            # 基準: 已發布的 App 還要在商店聲明; 資料安全性頁面列出每一類儲存的資料才算確認
            # 靜態確認不了同意在儲存之前、涵蓋所有存的資料 -> 不判符合, 列出商店聲明的比對結果供人工確認
            store = fetch_play_data_safety(a.get_package() or "")
            unconfirmed = storage_store_unconfirmed(storage, store)
            verdict = "NOT_EVALUATED"
            reason = ("consent mechanism found, but whether consent comes before storing and covers all stored data "
                      "cannot be confirmed statically; store declaration: %s"
                      % ("; ".join(unconfirmed) if unconfirmed else "all stored data types listed on Google Play"))
        elif consent:
            # 只有隱私權政策文字或聲明畫面: 有告知, 但無法確認儲存前有取得同意
            verdict, reason = "NOT_EVALUATED", "privacy notice found, but consent before storing could not be confirmed"
        elif high:
            verdict, reason = "WARNING", "sensitive data stored without any consent or notice mechanism"
        else:
            verdict, reason = "NOT_EVALUATED", "stored data may be sensitive, no consent or notice mechanism found"
        return {"storage": high, "review": review, "consent": consent, "own_classes": own,
                "verdict_086": verdict, "reason": reason}

    def invoke_target(out):
        """invoke 指令的目標 method, 去掉空白 (例 'Lcom/a/AESUtil;->encrypt(Ljava/lang/String;)Ljava/lang/String;')
        使用: lab_086, lab_087 (透過 find_sensitive_storage)"""
        m = re.search(r'(L[^;\s]+;->[^(\s]+\([^)]*\)\S+)$', out or "")
        return m.group(1).replace(" ", "") if m else ""

    def crypto_wrapper_methods(dx, keep):
        """App 自己的加解密函式: 有呼叫 Cipher.doFinal 且回傳物件, 再加一層呼叫它並回傳物件的 method
        回傳 {'Lcls;->name(desc)ret', ...}
        使用: lab_086, lab_087 (透過 find_sensitive_storage)"""
        found, callers = set(), {}
        for cls, ca in dx.classes.items():
            if not keep(cls):
                continue
            for ma in ca.get_methods():
                if ma.is_external():
                    continue
                try:
                    outs = [(ins.get_name(), ins.get_output()) for ins in ma.get_method().get_instructions()]
                except Exception:
                    continue
                if not any(n == "return-object" for n, _ in outs):
                    continue
                full = ("%s->%s%s" % (ma.class_name, ma.name, ma.descriptor)).replace(" ", "")
                if any("Ljavax/crypto/Cipher;->doFinal(" in o for _, o in outs):
                    found.add(full)
                else:
                    callers[full] = {invoke_target(o) for n, o in outs if n.startswith("invoke")}
        return found | {m for m, targets in callers.items() if targets & found}

    def sql_text_table(sql):
        """App 自己定義、名稱看不出用途的資料表, 有文字欄位 -> (表名, 說明), 否則 None
        sql_sensitive_columns 已認出的 (敏感欄位、訊息 / 筆記等表) 與系統表不算
        使用: lab_086, lab_087 (透過 find_sensitive_storage)"""
        m = re.match(r"\s*create\s+(?:virtual\s+)?table\s+(?:if\s+not\s+exists\s+)?[`\"\[]?([\w.]+)[`\"\]]?\s*\((.*)\)",
                     sql or "", re.I | re.S)
        if not m or sql_sensitive_columns(sql) or m.group(1).lower().startswith(("_new_", "room_", "android_", "sqlite_")) \
                or m.group(1) in LIB_TABLE_NAMES:
            return None
        cols = []
        for part in m.group(2).split(","):
            words = part.strip().split()
            if len(words) > 1 and words[1].strip("`\"[]").upper().startswith(("TEXT", "VARCHAR", "BLOB")) \
                    and words[0].upper() not in ("PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT"):
                cols.append(words[0].strip("`\"[]"))
        return (m.group(1), "table '%s', text columns: %s" % (m.group(1), ", ".join(cols[:6]))) if cols else None

    def storage_store_unconfirmed(items, store):
        """儲存的資料有哪些無法確認已在 Google Play 資料安全性聲明 -> 原因列表 (空 = 全部已聲明)
        頁面沒列出不算沒聲明 (on-device 資料 Google 不要求填, 商店說明也可能有寫), 只當作無法確認
        使用: lab_086 (透過 storage_consent_analyze)"""
        if not items:
            return []
        if store.get("status") != "ok":
            return ["Google Play data safety page: %s" % store.get("status")]
        declared = {c.lower() for c in store.get("declared", [])}
        missing = []
        for s in items:
            text = split_words("%s %s" % (s.get("data") or "", s.get("key") or ""))
            category = next((c for pattern, c in STORAGE_PLAY_CATEGORIES if re.search(pattern, text)), None)
            if category is None:
                note = "%s: no matching data safety category" % (s.get("data") or s.get("key"))
            elif category not in declared:
                note = "%s not listed" % category
            else:
                continue
            if note not in missing:
                missing.append(note)
        return missing[:5]

    def storage_items(items):
        """拿掉儲存結果中的 method 物件 (無法轉 JSON)
        使用: lab_086, lab_087"""
        return [{k: v for k, v in s.items() if k != "method"} for s in items]

    # ---- 加殼判斷 ----

    def missing_app_components(a, dx):
        """Manifest 宣告的 App 元件有多少不在 dex 裡; 過半 (suspected) 代表程式碼被加密、執行時才載入 (可抓未知的殼)
        使用: lab_042"""
        # 排除 Android / Google 等函式庫元件, 只看 App 自己的
        comps = ["L" + c.replace(".", "/") + ";"
                 for c in a.get_activities() + a.get_services() + a.get_receivers() + a.get_providers()]
        comps = [c for c in comps if app_class_filter(a)(c)]
        missing = [c for c in comps if c not in dx.classes]
        return {
            "suspected": len(comps) > 0 and len(missing) * 2 > len(comps),
            "app_components": len(comps),
            "missing_count": len(missing),
            "missing": missing[:10],
            "application": a.get_attribute_value("application", "name"),
        }

    # ---- 回傳格式 ----

    def app_code_hidden(a, dx):
        """App 自己的套件幾乎沒有 class, 也沒有被搬到短套件 -> 看不到 App 程式碼 (多半是加殼); 門檻同 lab_084
        使用: lab_027, lab_056"""
        prefixes = app_own_prefixes(a)
        classes = [name for name, ca in dx.classes.items() if not ca.is_external()]   # 外部引用不是 APK 裡看得到的程式碼
        own = sum(1 for c in classes if c.startswith(prefixes)) if prefixes else 0
        moved = sum(1 for c in classes if is_repackaged_class(c))
        return own < OBF_MIN_CLASSES and moved < OBF_REPACKAGED_MIN

    # 視窗有效的 Activity 生命週期: 頁面顯示前會執行 (onPause 離開時才設, 頁面顯示中沒有保護, 不算)
    # 使用: lab_027 (透過 flag_secure_coverage)
    SCREEN_LIFECYCLE_METHODS = {"attachBaseContext", "onCreate", "onPostCreate", "onStart", "onResume", "onAttachedToWindow"}
    SCREEN_CALLBACK_METHODS = {"onActivityPreCreated", "onActivityCreated", "onActivityStarted", "onActivityResumed"}

    def app_pages(a, dx, keep):
        """App 自己的 Activity (第三方 SDK 的畫面不算), 回傳 (程式碼看得到的, Manifest 有宣告但不在 dex 裡的)
        使用: lab_027 (透過 screen_capture_verdict)"""
        package, prefixes = a.get_package() or "", app_own_prefixes(a)
        pages, not_visible = [], []
        for name in a.get_activities():
            class_name = "L" + resolve_activity_name(package, name).replace(".", "/") + ";"
            # 自己的套件優先 (org.* 這類前綴也會被通用過濾排除, 頁面算少就可能誤判 PASS)
            if not (class_name.startswith(prefixes) if prefixes else keep(class_name)):
                continue
            ca = dx.classes.get(class_name)
            (pages if ca and not ca.is_external() else not_visible).append(class_name)
        return pages, not_visible

    def class_chain(dx, class_name):
        """class 自己和 APK 內看得到的父類別
        使用: lab_027 (透過 screen_capture_verdict)"""
        chain = []
        while class_name not in chain:
            ca = dx.classes.get(class_name)
            if not ca or ca.is_external():
                break
            chain.append(class_name)
            class_name = str(ca.get_vm_class().get_superclassname())
        return chain

    def flag_secure_coverage(dx, ref, page_classes, depth=4):
        """從設定 FLAG_SECURE 的呼叫往上追, 回傳 (經過的頁面生命週期所在 class, 是否由 ActivityLifecycleCallbacks 套用到所有頁面,
        是否有路徑追不到頁面; 例如 Fragment 或按鈕事件, 可能還涵蓋其他頁面)
        使用: lab_027 (透過 screen_capture_verdict)"""
        ca = dx.classes.get(ref["class"])
        level = [m for m in ca.get_methods() if m.name == ref["method"] and not m.is_external()] if ca else []
        seen, classes, is_global, open_end = set(), set(), False, not level
        for _ in range(depth + 1):
            callers = []
            for m in level:
                if m in seen:
                    continue
                seen.add(m)
                owner = str(m.class_name)
                if m.name in SCREEN_LIFECYCLE_METHODS and owner in page_classes:
                    classes.add(owner)
                elif m.name in SCREEN_CALLBACK_METHODS:
                    is_global = True
                else:
                    from_methods = [caller for _c, caller, _o in m.get_xref_from()]
                    open_end = open_end or not from_methods
                    callers += from_methods
            level = callers
        return classes, is_global, open_end or any(m not in seen for m in level)

    def screen_capture_verdict(a, dx, keep, secure, is_conditional, unknown, recents, warnings):
        """依 MAS 4.1.2.3.9 判定 lab_027, 回傳 (verdict, reason, review, pages); 規則見 detect_lab_027
        使用: lab_027"""
        pages, not_visible = app_pages(a, dx, keep)
        result_pages = {"total": len(pages), "covered": [], "without_flag": [], "not_visible": not_visible}
        if app_code_hidden(a, dx):
            return "NOT_EVALUATED", "code_not_visible", [], result_pages
        chains = {page: class_chain(dx, page) for page in pages}
        page_classes = {c for chain in chains.values() for c in chain}
        covered_classes, maybe_classes = set(), set()
        is_global, maybe_all = False, False
        uncertain, untraced = [], []
        for ref, certain in [(r, not is_conditional(r)) for r in secure] + [(r, False) for r in unknown]:
            classes, applies_to_all, open_end = flag_secure_coverage(dx, ref, page_classes)
            if certain:
                covered_classes |= classes
                is_global = is_global or applies_to_all
            else:
                maybe_classes |= classes
                maybe_all = maybe_all or applies_to_all
            if not certain or not (classes or applies_to_all):
                uncertain.append(ref)
            elif open_end:
                untraced.append(ref)
            maybe_all = maybe_all or open_end
        covered = [p for p in pages if is_global or covered_classes & set(chains[p])]
        result_pages["covered"] = covered
        if pages and len(covered) == len(pages) and not uncertain and not not_visible:
            return "PASS", None, [], result_pages
        if secure or unknown:
            # 其他呼叫都不可能涵蓋、也沒有警示加切換畫面遮蔽的頁面, 才算確定沒設
            missing = [] if maybe_all or (recents and warnings) else [
                p for p in pages if p not in covered and not maybe_classes & set(chains[p])]
            if missing:
                result_pages["without_flag"] = missing
                return "WARNING", "page_without_flag", [], result_pages
            review = [{"where": "%s.%s" % (r["class"], r["method"]),
                       "note": "SurfaceView.setSecure protects only that view" if r["api"].endswith("setSecure") else "may not apply to every page"}
                      for r in uncertain + untraced]
            review += [{"where": p, "note": "not in the code"} for p in not_visible]
            review += [{"where": p, "note": "FLAG_SECURE set"} for p in covered]
            return "NOT_EVALUATED", "partial", review, result_pages
        if recents and warnings:
            review = [{"where": "%s.%s" % (r["class"], r["method"]), "note": r["api"].split("->")[-1]} for r in warnings + recents]
            return "NOT_EVALUATED", "warning_and_recents", review, result_pages
        if not_visible and not pages:
            return "NOT_EVALUATED", "partial", [{"where": p, "note": "not in the code"} for p in not_visible], result_pages
        return "WARNING", "recents_only" if recents else ("warning_only" if warnings else None), [], result_pages

    def protection_result(lab_id, description, code_evidence, api_evidence, keep, reason=None, review=None,
                          verdict=None, extra=None):
        """「缺少防護」類檢測的統一回傳: 有證據 -> PASS, 沒有 -> WARNING;
        沒有證據但端點給了 reason (靜態無法確定) -> NOT_EVALUATED, review 列出要人工確認的位置;
        verdict 有給就照用 (lab_027, lab_056 自己判定; lab_056 有證據也是 NOT_EVALUATED)
        使用: lab_026, lab_027, lab_056, lab_064 (reason / review / verdict 只有 lab_027, lab_056 用; extra 只有 lab_027 用)"""
        implemented = bool(code_evidence or api_evidence)
        verdict = verdict or ("PASS" if implemented else ("NOT_EVALUATED" if reason else "WARNING"))
        return jsonify(dict(extra or {}, **{
            "verdict":       verdict,
            "has_finding":   verdict == "WARNING",   # True = 缺少防護
            "implemented":   implemented,
            "reason":        None if verdict == "PASS" else reason,
            "review":        (review or []) if verdict == "NOT_EVALUATED" else [],
            "code_evidence": code_evidence,
            "api_evidence":  api_evidence,
            "scanned_app_classes": count_app_classes(dx, keep),
            "count":         len(code_evidence) + len(api_evidence),
            "lab_id":        lab_id,
            "description":   description,
        })), 200

    def share_check_result(lab_id, description, channels, dx, keep):
        """lab_039 / 040 的回傳: 每個管道的 problem 由端點填 (None = 沒問題)
        確定的管道 (confidence high) 有問題且確定是敏感資料 -> WARNING;
        只有待確認的管道有問題 (接收者不明、開關看不出、看不出是否敏感) -> NOT_EVALUATED (報告顯示 Not evaluated); 都沒有 -> PASS
        使用: lab_039, lab_040"""
        flagged = [c for c in channels if c["problem"]]
        findings = [c for c in flagged
                    if c["confidence"] == "high" and not c.get("unverified") and c.get("sensitive")]
        review = [c for c in flagged if c not in findings]
        return jsonify({
            "verdict":       "WARNING" if findings else ("NOT_EVALUATED" if review else "PASS"),
            "has_finding":   bool(findings),
            "channels":      channels,
            "findings":      findings,
            "review":        review,
            "scanned_app_classes": count_app_classes(dx, keep),
            "count":         len(findings),
            "lab_id":        lab_id,
            "description":   description,
        }), 200

    # ---- 引用函式庫已知漏洞 ----

    # MAS 4.1.5.3.1 備註: 具 CVE 且 CVSS v3.0 >= 7 (High / Critical); v3.1 公式與等級門檻相同, 一起採用
    # 使用: lab_016
    LIB_CVSS_THRESHOLD = 7.0

    # 對外查詢上限: OSV 批次查詢 1 次 + 漏洞明細; NVD 未帶 API key 時每 30 秒限 5 次 (超過會自動等待)
    # 使用: lab_016
    LIB_MAX_SECONDS = 150
    LIB_MAX_OSV_DETAILS = 400
    LIB_MAX_NVD_REQUESTS = 20

    # NVD 查到的 CVSS 分數存在本機 7 天, 同一個 CVE 不重複查 (NVD 沒有 API key 時有次數限制)
    # 使用: lab_016
    LIB_NVD_CACHE = '/tmp/cmaa_lab016_nvd_cache.json'
    LIB_NVD_CACHE_DAYS = 7

    # 會判 Failed 的 CVE, 分數最高的前幾個再用 NVD (NIST 官方) 分數確認; 其餘或查不到的保留 OSV (GitHub 審核) 分數
    # 使用: lab_016
    LIB_MAX_NVD_CONFIRM = 5

    # 原生函式庫版本字串 -> (名稱, regex, NVD CPE vendor:product, 只看這個檔名 (None = 所有 .so))
    # 版本字串是各函式庫原始碼裡的固定格式 (例如 expat 的 XML_ExpatVersion() 回傳 expat_2.4.1); CPE 名稱已用 NVD 查證
    # 使用: lab_016 (透過 library_inventory)
    LIB_NATIVE_BANNERS = (
        ('openssl', re.compile(rb'OpenSSL ([0-9]+\.[0-9]+\.[0-9]+[a-z]?)[ \x00]'), 'openssl:openssl', None),
        ('sqlite', re.compile(rb'SQLite(?: version)?[ /:]+([0-9]+\.[0-9]+\.[0-9]+)(?![0-9A-Za-z.+-])'), 'sqlite:sqlite', None),
        ('zlib', re.compile(rb'(?:de|in)flate ([0-9]+\.[0-9]+(?:\.[0-9]+){0,2}) Copyright'), 'zlib:zlib', None),
        ('libpng', re.compile(rb'libpng version ([0-9]+\.[0-9]+\.[0-9]+)(?![0-9A-Za-z.+-])'), 'libpng:libpng', None),
        ('libwebp', re.compile(rb'libwebp[ /:-]+([0-9]+\.[0-9]+\.[0-9]+)(?![0-9A-Za-z.+-])'), 'webmproject:libwebp', None),
        ('libcurl', re.compile(rb'libcurl/([0-9]+\.[0-9]+\.[0-9]+)(?![0-9A-Za-z.+-])'), 'haxx:libcurl', None),
        ('mbedtls', re.compile(rb'[Mm]bed TLS ([0-9]+\.[0-9]+\.[0-9]+)(?![0-9A-Za-z.+-])'), 'arm:mbed_tls', None),
        ('expat', re.compile(rb'expat_([0-9]+\.[0-9]+\.[0-9]+)(?![0-9A-Za-z.+-])'), 'libexpat_project:libexpat', None),
        ('libtiff', re.compile(rb'LIBTIFF, Version ([0-9]+\.[0-9]+\.[0-9]+)(?![0-9A-Za-z.+-])'), 'libtiff:libtiff', None),
        ('libvpx', re.compile(rb'WebM Project VP[89] (?:En|De)coder v([0-9]+\.[0-9]+\.[0-9]+)(?![0-9A-Za-z.+-])'), 'webmproject:libvpx', None),
        ('libarchive', re.compile(rb'libarchive ([0-9]+\.[0-9]+\.[0-9]+)(?![0-9A-Za-z.+-])'), 'libarchive:libarchive', None),
        ('opus', re.compile(rb'libopus ([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?![0-9A-Za-z.+-])'), 'opus-codec:opus', None),
        # Unity 引擎版本 (2021.3.16f1、6000.0.23f1), 只看 libunity.so
        ('unity', re.compile(rb'((?:20[12][0-9]|6000)\.[0-9]+\.[0-9]+[abfp][0-9]+)(?![0-9A-Za-z.+-])'), 'unity:editor', 'libunity.so'))

    # libwebp CVE-2023-4863 特徵: 內部符號 VP8LBuildHuffmanTable 在、修補後才有的 VP8LHuffmanTablesAllocate 不在 -> 未修補
    # 只有 WebPCopyPlane 等對外 API 時 (內部符號被拿掉) 無法判斷
    # 使用: lab_016 (透過 library_inventory)
    LIB_WEBP_CVE = {'cve': 'CVE-2023-4863', 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H'}

    # Google 函式庫根目錄 xxx.properties 的 client 前綴 -> Maven group
    # 使用: lab_016 (透過 library_inventory)
    LIB_PROPERTIES_GROUPS = (('firebase-', 'com.google.firebase'), ('play-services-', 'com.google.android.gms'),
                             ('transport-', 'com.google.android.datatransport'))

    LIB_VERSION_RE = re.compile(r'[0-9]+(?:\.[0-9]+){1,3}(?:-[A-Za-z0-9.]+)?')

    # 沒有版本檔、但 OSV 上有 CVSS v3 >= 7 漏洞的常見函式庫: (Maven 套件, 代表類別, 版本來源, 最低版本特徵)
    # 代表類別: 結尾 ';' 是完整類別, 結尾 '/' 是套件 (不算例外類別; R8 常只留下例外類別, 那不算有引用)
    # 版本來源: ('class', 類別) 取該類別裡的版本字串; ('strings', regex) 搜尋 DEX 字串
    # 最低版本特徵: (類別, 該類別從哪一版開始有), 有這個類別就表示版本至少是這一版
    # 使用: lab_016 (透過 dex_libraries)
    LIB_DEX_SIGNATURES = (
        (('com.google.code.gson:gson',), ('Lcom/google/gson/Gson;', 'Lcom/google/gson/GsonBuilder;', 'Lcom/google/gson/JsonParser;'),
         None, (('Lcom/google/gson/ToNumberPolicy;', '2.8.9'),)),
        (('com.fasterxml.jackson.core:jackson-databind',), ('Lcom/fasterxml/jackson/databind/ObjectMapper;',),
         ('class', 'Lcom/fasterxml/jackson/databind/cfg/PackageVersion;'), ()),
        (('com.fasterxml.jackson.core:jackson-core',), ('Lcom/fasterxml/jackson/core/JsonFactory;',),
         ('class', 'Lcom/fasterxml/jackson/core/json/PackageVersion;'), ()),
        (('com.squareup.okhttp3:okhttp',), ('Lokhttp3/OkHttpClient;',),
         ('strings', re.compile(r'okhttp/([3-9]\.[0-9]+\.[0-9]+)')), ()),
        (('com.squareup.retrofit2:retrofit',), ('Lretrofit2/Retrofit;',), None, ()),
        (('org.bouncycastle:bcprov-jdk15on', 'org.bouncycastle:bcprov-jdk18on'),
         ('Lorg/bouncycastle/crypto/', 'Lorg/bouncycastle/asn1/', 'Lorg/bouncycastle/jce/provider/'),
         ('strings', re.compile(r'BouncyCastle Security Provider v([0-9]+\.[0-9]+(?:\.[0-9]+)?)')), ()),
        (('com.google.protobuf:protobuf-javalite', 'com.google.protobuf:protobuf-java'),
         ('Lcom/google/protobuf/CodedInputStream;', 'Lcom/google/protobuf/GeneratedMessageLite;'), None, ()),
        (('org.jsoup:jsoup',), ('Lorg/jsoup/Jsoup;', 'Lorg/jsoup/parser/Parser;', 'Lorg/jsoup/nodes/Document;'), None, ()),
        (('commons-io:commons-io',), ('Lorg/apache/commons/io/IOUtils;', 'Lorg/apache/commons/io/FileUtils;'), None, ()),
        (('org.apache.commons:commons-text',), ('Lorg/apache/commons/text/',), None, ()),
        (('org.apache.commons:commons-compress',), ('Lorg/apache/commons/compress/',), None, ()),
        (('org.yaml:snakeyaml',), ('Lorg/yaml/snakeyaml/',), None, ()),
        (('org.apache.logging.log4j:log4j-core',), ('Lorg/apache/logging/log4j/core/',), None, ()),
        (('com.nimbusds:nimbus-jose-jwt',), ('Lcom/nimbusds/jose/',), None, ()),
        (('net.minidev:json-smart',), ('Lnet/minidev/json/',), None, ()),
        (('org.apache.httpcomponents:httpclient',), ('Lorg/apache/http/impl/client/',), None, ()))

    # 網頁 (JavaScript) 函式庫: (npm 套件, 檔案內容 regex, 檔名 regex), (?P<v>§) 是版本
    # 規則取自 Retire.js 的 jsrepository (Apache-2.0, 只取有 npm 套件的函式庫), 另加 KaTeX 與壓縮後的 DOMPurify
    # 使用: lab_016 (透過 js_libraries)
    LIB_JS_SIGNATURES = (
        ('@angular/core', ('/\\*\\*[\\s*]+@license Angular v(?P<v>§)', '\\[[\'"]ng-version[\'"],[\'"](?P<v>§)[\'"]\\]'), ()),
        ('alasql', ('/\\*!?[ \n]*AlaSQL v(?P<v>§)',), ('alasql-(?P<v>§)(\\.min)?\\.js',)),
        ('alpinejs', ('version:[\'"](?P<v>§)[\'"],flushAndStopDeferringMutations',), ('alpine(?:js)?[-.](?P<v>§)(.min)?.js',)),
        ('angular', ('/\\*[\\*\\s]+(?:@license )?AngularJS(?: NES)? v(?P<v>§)', 'http://errors\\.angularjs\\.org/(?P<v>§)/'), ('angular(?:js)?-(?P<v>§)(.min)?\\.js',)),
        ('axios', ('/\\*!? *[Aa]xios v(?P<v>§) ', '// Axios v(?P<v>§) C', 'return"\\[Axios v(?P<v>§)\\] Transitional', '\\"axios\\",\\"version\\":\\"(?P<v>§)\\"'), ('axios-(?P<v>§)(\\.min)?\\.js',)),
        ('backbone', ('//[ ]+Backbone.js (?P<v>§)', 'a=t.Backbone=\\{\\}\\}a.VERSION="(?P<v>§)"', 'Backbone\\.VERSION *= *["\'](?P<v>§)["\']'), ('backbone(?:js)?-(?P<v>§)(.min)?\\.js',)),
        ('blueimp-file-upload', ('/\\*[\\s*]+jQuery File Upload User Interface Plugin (?P<v>§)[\\s*]+https://github.com/blueimp',), ()),
        ('bootstrap', ('/\\*!? Bootstrap v(?P<v>§)', '\\* Bootstrap v(?P<v>§)', '/\\*! Bootstrap v(?P<v>§)', 'this\\.close\\)\\};.\\.VERSION="(?P<v>§)"(?:,.\\.TRANSITION_DURATION=150)?,.\\.prototype\\.close'), ('bootstrap-(?P<v>§)(\\.min)?\\.js',)),
        ('bootstrap-select', ('/\\*![\\s]+\\*[\\s]+Bootstrap-select[\\s]+v(?P<v>§)', '.\\.data\\("selectpicker",.=new .\\(this,.\\)\\)\\}"string"==typeof .&&\\(.=.\\[.\\]instanceof Function\\?.\\[.\\]\\.apply\\(.,.\\):.\\.options\\[.\\]\\)\\}\\}\\);return void 0!==.\\?.:.\\}.\\.VERSION="(?P<v>§)",'), ()),
        ('c3', ('[\\s]+var c3 ?= ?\\{ ?version: ?[\'"](?P<v>§)[\'"] ?\\};[\\s]+var c3_chart_fn,',), ()),
        ('chart.js', ('var version="(?P<v>§)";const KNOWN_POSITIONS=\\["top","bottom","left","right","chartArea"\\]', '/\\*![\\s]+\\* Chart.js v(?P<v>§)', '/\\*![\\s]+\\* Chart.js[\\s]+\\* http://chartjs.org/[\\s]+\\* Version: (?P<v>§)'), ()),
        ('ckeditor4', ('ckeditor..js.{4,30}=\\{timestamp:"[^"]+",version:"(?P<v>§)', 'window\\.CKEDITOR=function\\(\\)\\{var [a-z]=\\{timestamp:"[^"]+",version:"(?P<v>§)'), ('ckeditor-(?P<v>§)(\\.min)?\\.js',)),
        ('ckeditor5', ('const .="(?P<v>§)"[,;].{0,140}?\\.CKEDITOR_VERSION=.;', 'CKEDITOR_VERSION="(?P<v>§)"'), ('ckeditor5-(?P<v>§)(\\.min)?\\.js',)),
        ('d3', ('\\/\\/ https:\\/\\/d3js\\.org (?:v|Version )(?P<v>§) ',), ('d3[-.](?P<v>§)(.min)?.js',)),
        ('datatables.net', ('http://www.datatables.net\n +DataTables (?P<v>§)', '/\\*! DataTables (?P<v>§)', '.\\.version="(?P<v>§)";[\\s]*.\\.settings=\\[\\];[\\s]*.\\.models=\\{[\\s]*\\};[\\s]*.\\.models.oSearch'), ('jquery.dataTables-(?P<v>§)(\\.min)?\\.js',)),
        ('dojo', (), ('dojo-(?P<v>§)(\\.min)?\\.js',)),
        ('dompurify', ("DOMPurify.version = '(?P<v>§)';", 'DOMPurify.version="(?P<v>§)"', 'DOMPurify=.[^\\r\\n]{10,850}?\\.version="(?P<v>§)"', '/\\*! @license DOMPurify (?P<v>§)', 'var .="dompurify"+.{10,550}?\\.version="(?P<v>§)"', '\\.version="(?P<v>§)",\\w+\\.removed=\\[\\]'), ()),
        ('echarts', ("'(?P<v>§)';[\\s]+var dependencies = \\{[\\s]+zrender: '[0-9.]+'[\\s]+\\};[\\s]+var TEST_FRAME_REMAIN_TIME = 1;", 'setPlatformAPI=[a-zA-Z_]+,.\\.throttle=[a-zA-Z_]+,.\\.time=[a-zA-Z_]+,.\\.use=[a-zA-Z_]+,.\\.util=[a-zA-Z_]+,.\\.vector=[a-zA-Z_]+,.\\.version=[\'"](?P<v>§)[\'"],.\\.zrUtil', '.\\.throttle=[a-zA-Z_]+,.\\.time=[a-zA-Z_]+,.\\.util=[a-zA-Z_]+,.\\.vector=[a-zA-Z_]+,.\\.version=[\'"](?P<v>§)[\'"],.\\.zrender'), ('echarts[-.](?P<v>§)(.min)?.js',)),
        ('ember-source', ('Project:   Ember -(?:.*\n){9,11}// Version: v(?P<v>§)', '// Version: v(?P<v>§)(.*\n){10,15}(Ember Debug|@module ember|@class ember)', 'Ember.VERSION[ ]?=[ ]?(?:\'|")(?P<v>§)(?:\'|")', 'meta\\.revision="Ember@(?P<v>§)"', 'e\\("ember/version",\\["exports"\\],function\\(e\\)\\{"use strict";?[\\s]*e(?:\\.|\\[")default(?:"\\])?="(?P<v>§)"', '\\("ember/version",\\["exports"\\],function\\(e\\)\\{"use strict";.{1,70}\\.default="(?P<v>§)"', '/\\*![\\s]+\\* @overview  Ember - JavaScript Application Framework[\\s\\S]{0,400}\\* @version   (?P<v>§)', '// Version: (?P<v>§)[\\s]+\\(function\\(\\) *\\{[\\s]*/\\*\\*[\\s]+@module ember[\\s]', 'Object\\.defineProperty\\(\\{__proto__:null,CI:!1,DEBUG:!1\\},Symbol\\.toStringTag,\\{value:"Module"\\}\\),\\w+="(?P<v>§)"', 'isLowLevelRegister:function\\(e\\)\\{return e<=3\\}\\},Symbol\\.toStringTag,\\{value:"Module"\\}\\),\\w+="(?P<v>§)"'), ('ember-(?P<v>§)(\\.min)?\\.js',)),
        ('froala-editor', ('/\\*![\\s]+\\* froala_editor v(?P<v>§)', 'VERSION:"(?P<v>§)",INSTANCES:\\[\\],OPTS_MAPPING:\\{\\}'), ()),
        ('handlebars', ('Handlebars.VERSION = "(?P<v>§)";', 'Handlebars=\\{VERSION:(?:\'|")(?P<v>§)(?:\'|")', 'this.Handlebars=\\{\\};[\n\r \t]+\\(function\\([a-z]\\)\\{[a-z].VERSION=(?:\'|")(?P<v>§)(?:\'|")', 'exports.HandlebarsEnvironment=[\\s\\S]{70,120}exports.VERSION=(?:\'|")(?P<v>§)(?:\'|")', '/\\*+![\\s]+(?:@license)?[\\s]+handlebars v+(?P<v>§)', 'window\\.Handlebars=.,.\\.VERSION="(?P<v>§)"', '.\\.HandlebarsEnvironment=.;var .=.\\(.\\),.=.\\(.\\),.="(?P<v>§)";.\\.VERSION='), ('handlebars(?:js)?-(?P<v>§)(.min)?\\.js',)),
        ('highcharts', ('product:"Highcharts",version:"(?P<v>§)"', 'product="Highcharts"[,;].\\.version="(?P<v>§)"'), ()),
        ('highlight.js', ('/\\*!\\s*[Hh]ighlight.js v(?P<v>§)', '"after:highlightBlock"[\\s\\S]{0,170}versionString=[\'"](?P<v>§)[\'"]'), ('highlight[-.](?P<v>§)(.min)?.js',)),
        ('jquery', ('/\\*!? jQuery v(?P<v>§)', '\\* jQuery JavaScript Library v(?P<v>§)', '\\* jQuery (?P<v>§) - New Wave Javascript', '/\\*![\\s]+\\* jQuery JavaScript Library v(?P<v>§)', '// \\$Id: jquery.js,v (?P<v>§)', '/\\*! jQuery v(?P<v>§)', '[^a-z]f="(?P<v>§)",.*[^a-z]jquery:f,', '[^a-z]m="(?P<v>§)",.*[^a-z]jquery:m,', '[^a-z.]jquery:[ ]?"(?P<v>§)"', '\\$\\.documentElement,Q=e.jQuery,Z=e\\.\\$,ee=\\{\\},te=\\[\\],ne="(?P<v>§)"', '="(?P<v>§)",.{50,300}(.)\\.fn=(\\2)\\.prototype=\\{jquery:'), ('jquery-(?P<v>§)(\\.min)?\\.js',)),
        ('jquery-migrate', ('/\\*!?(?:\n \\*)? jQuery Migrate(?: -)? v(?P<v>§)', '\\.migrateVersion ?= ?"(?P<v>§)"[\\s\\S]{10,150}(migrateDisablePatches|migrateWarnings|JQMIGRATE)', 'jQuery\\.migrateVersion ?= ?"(?P<v>§)"'), ('jquery-migrate-(?P<v>§)(.min)?\\.js',)),
        ('jquery-mobile', ('/\\*!?[\\s*]*jQuery Mobile(?: -)? v?(?P<v>§)', '// Version of the jQuery Mobile Framework[\\s]+version: *["\'](?P<v>§)["\'],'), ('jquery.mobile-(?P<v>§)(.min)?\\.js',)),
        ('jquery-ui', ('/\\*!? jQuery UI - v(?P<v>§)', '/\\*!?[\n *]+jQuery UI (?P<v>§)', '/\\*!? jQuery UI - v(?P<v>§)(.*\n){1,3}.*jquery\\.ui\\.autocomplete\\.js', '/\\*!?[\n *]+jQuery UI (?P<v>§)(.*\n)*.*\\.ui\\.autocomplete', '/\\*!?[\n *]+jQuery UI Autocomplete (?P<v>§)', '/\\*!? jQuery UI - v(?P<v>§)(.*\n){1,3}\\* Includes: .* autocomplete\\.js', '/\\*!? jQuery UI - v(?P<v>§)(.*\n){1,3}.*jquery\\.ui\\.dialog\\.js', '/\\*!?[\n *]+jQuery UI (?P<v>§)(.*\n)*.*\\.ui\\.dialog', '/\\*!?[\n *]+jQuery UI Dialog (?P<v>§)', '/\\*!? jQuery UI - v(?P<v>§)(.*\n){1,3}\\* Includes: .* dialog\\.js', '/\\*!? jQuery UI - v(?P<v>§)(.*\n){1,3}.*jquery\\.ui\\.tooltip\\.js', '/\\*!?[\n *]+jQuery UI (?P<v>§)(.*\n)*.*\\.ui\\.tooltip', '/\\*!?[\n *]+jQuery UI Tooltip (?P<v>§)'), ()),
        ('jquery-validation', ('/\\*!?(?:\n \\*)?[\\s]*jQuery Validation Plugin -? ?v(?P<v>§)', 'Original file: /npm/jquery-validation@(?P<v>§)/dist/jquery.validate.js'), ('jquery.validat(?:ion|e)-(?P<v>§)(.min)?\\.js',)),
        ('jquery.terminal', ('version (?P<v>§)[\\s]+\\*[\\s]+\\* This file is part of jQuery Terminal.', '\\$\\.terminal=\\{version:"(?P<v>§)"'), ()),
        ('jszip', ('/\\*![\\s]+JSZip v(?P<v>§) ',), ('jszip-(?P<v>§)(\\.min)?\\.js',)),
        ('katex', ('version:"(?P<v>§)",render:',), ()),
        ('knockout', ('(?:\\*|//) Knockout JavaScript library v(?P<v>§)', '.version="(?P<v>§)",_.b\\(.version.,_.version\\),_.options=\\{deferUpdates:!1,useOnlyNativeEvents:!1,foreachHidesDestroyed:!1\\}'), ('knockout-(?P<v>§)(.min)?\\.js',)),
        ('lodash', ('/\\*[\\s*!]+(?:@license)?[\\s*]+(?:Lo-Dash|lodash|Lodash) v?(?P<v>§)[\\s\\S]{1,200}Build: `lodash modern -o', '/\\*[\\s*!]+(?:@license)?[\\s*]+(?:Lo-Dash|lodash|Lodash) v?(?P<v>§) <', '/\\*[\\s*!]+(?:@license)?[\\s*]+(?:Lo-Dash|lodash|Lodash) v?(?P<v>§) lodash.com/license', '/\\*[\\s*]+@license[\\s*]+(?:Lo-Dash|lodhash|Lodash)[\\s\\S]{1,500}var VERSION *= *[\'"](?P<v>§)[\'"]', 'var VERSION="(?P<v>§)";var BIND_FLAG=1,BIND_KEY_FLAG=2,CURRY_BOUND_FLAG=4,CURRY_FLAG=8'), ()),
        ('markdown-it', ('/\\*! markdown-it(?:-ins)? (?P<v>§)',), ('markdown-it-(?P<v>§)(\\.min)?\\.js',)),
        ('marked', ('/[!*\\s/]+[\\s]marked v(?P<v>§)',), ('marked[-.](?P<v>§)(.min)?.js',)),
        ('mathjax', ('\\.MathJax\\.config\\.startup;{10,100}.\\.VERSION="(?P<v>§)"', '\\.MathJax=\\{version:"(?P<v>§)"', 'MathJax.{0,100}.\\.VERSION=void 0,.\\.VERSION="(?P<v>§)"', 'MathJax\\.version="(?P<v>§)";', '\\.mathjaxVersion="(?P<v>§)"'), ()),
        ('moment', ('//!? moment.js(?:[\n\r]+)//!? version : (?P<v>§)', '/\\* Moment.js +\\| +version : (?P<v>§) \\|', '\\.version="(?P<v>§)".{20,60}"isBefore".{20,60}"isAfter".{200,500}\\.isMoment=', '\\.version="(?P<v>§)".{20,300}duration.{2,100}\\.isMoment=', '\\.isMoment\\(.{50,400}_isUTC.{50,400}="(?P<v>§)"', '="(?P<v>§)".{300,1000}Years:31536e6.{60,80}\\.isMoment', '// Moment.js is freely distributable under the terms of the MIT license.[\\s]+//[\\s]+// Version (?P<v>§)'), ('moment(?:-|\\.)(?P<v>§)(?:-min)?\\.js',)),
        ('mustache', ('name:\\s*[\'"]mustache.js[\'"],\\s*version:\\s*[\'"](?P<v>§)[\'"]', 'name="mustache.js"[;,].\\.version="(?P<v>§)"', '[^a-z]mustache.version[ ]?=[ ]?(?:\'|")(?P<v>§)(?:\'|")', 'exports.name[ ]?=[ ]?"mustache.js";[\n ]*exports.version[ ]?=[ ]?(?:\'|")(?P<v>§)(?:\'|");'), ('mustache(?:js)?-(?P<v>§)(.min)?\\.js',)),
        ('next', ('version="(?P<v>§)".{1,1500}document\\.getElementById\\("__NEXT_DATA__"\\)\\.textContent', 'document\\.getElementById\\("__NEXT_DATA__"\\)\\.textContent\\);window\\.__NEXT_DATA__=.;.\\.version="(?P<v>§)"', '="(?P<v>§)"[\\s\\S]{10,100}Component[\\s\\S]{1,10}componentDidCatch[\\s\\S]{10,30}componentDidMount'), ()),
        ('pdfjs-dist', ('(?:const|var) pdfjsVersion = [\'"](?P<v>§)[\'"];', 'PDFJS.version ?= ?[\'"](?P<v>§)[\'"]', 'apiVersion: ?[\'"](?P<v>§)[\'"][\\s\\S]*,data(:[a-zA-Z.]{1,6})?,[\\s\\S]*password(:[a-zA-Z.]{1,10})?,[\\s\\S]*disableAutoFetch(:[a-zA-Z.]{1,22})?,[\\s\\S]*rangeChunkSize', 'messageHandler\\.sendWithPromise\\("GetDocRequest",\\{docId:[a-zA-Z],apiVersion:"(?P<v>§)"', 'const version = [\'"](?P<v>§)[\'"];\\s*const build ='), ()),
        ('pdfobject', ('\\* +PDFObject v(?P<v>§)', '/*[\\s]+PDFObject v(?P<v>§)', 'let pdfobjectversion = "(?P<v>§)";', 'pdfobjectversion:"(?P<v>§)"'), ()),
        ('plupload', ('\\* Plupload - multi-runtime File Uploader(?:\r|\n)+ \\* v(?P<v>§)', 'var g=\\{VERSION:"(?P<v>§)",.*;window.plupload=g\\}'), ('plupload-(?P<v>§)(.min)?\\.js',)),
        ('protobufjs', ('protobuf\\.js v(?P<v>§)',), ('protobuf-(?P<v>§)(?:\\.min)?\\.js',)),
        ('quill', ('Quill Editor v(?P<v>§)', 'static version="(?P<v>§)";static imports=\\{delta:[^,]{1,20},parchment:'), ('quill-(?P<v>§)(?:\\.min)?\\.js',)),
        ('react', ('/\\*\\*\n +\\* React \\(with addons\\) ?v(?P<v>§)', '/\\*\\*\n +\\* React v(?P<v>§)', '/\\*\\* @license React v(?P<v>§)[\\s]*\\* react(-jsx-runtime)?\\.', '"\\./ReactReconciler":[0-9]+,"\\./Transaction":[0-9]+,"fbjs/lib/invariant":[0-9]+\\}\\],[0-9]+:\\[function\\(require,module,exports\\)\\{"use strict";module\\.exports="(?P<v>§)"\\}', 'ReactVersion\\.js[\\*! \\\\/\n\r]{0,100}function\\(e,t\\)\\{"use strict";e\\.exports="(?P<v>§)"', 'expected a ReactNode.[\\s\\S]{0,1800}?function\\(e,t\\)\\{"use strict";e\\.exports="(?P<v>§)"'), ()),
        ('react-dom', ('version:"(?P<v>§)[a-z0-9\\-]*"[\\s,]*rendererPackageName:"react-dom"', '/\\*\\* @license React v(?P<v>§)[\\s]*\\* react-dom\\.', 'return[\\s]+ReactSharedInternals.[a-zA-Z].useHostTransitionStatus\\(\\)[;]?[\\s]*\\}[;,][\\s]*exports.version[\\s]*=[\\s]*"(?P<v>§)"'), ()),
        ('select2', ('/\\*!(?:[\\s]+\\*)? Select2 (?P<v>§)', '/\\*[\\s]+Copyright 20[0-9]{2} [I]gor V[a]ynberg[\\s]+Version: (?P<v>§)[\\s\\S]{1,5000}(\\.attr\\("class","select2-sizer"|\\.data\\(document, *"select2-lastpos"|document\\)\\.data\\("select2-lastpos"|SingleSelect2, *MultiSelect2|window.Select2 *!== *undefined)'), ()),
        ('svelte', ('generated by Svelte v\\$\\{[\'"](?P<v>§)[\'"]\\}', 'generated by Svelte v(?P<v>§) \\*/', "version: '(?P<v>§)' [\\s\\S]{80,200}'SvelteDOMInsert'", "VERSION = '(?P<v>§)'[\\s\\S]{21,200}parse\\$[0-9][\\s\\S]{10,80}preprocess", 'var version\\$[0-9] = "(?P<v>§)";[\\s\\S]{10,30}normalizeOptions\\(options\\)[\\s\\S]{80,200}\'SvelteComponent.html\''), ('svelte[@\\-](?P<v>§)(.min)?\\.m?js',)),
        ('swiper', ('\\* Swiper (?P<v>§)',), ('swiper[-.](?P<v>§)(.min)?.js',)),
        ('tableexport.jquery.plugin', ('/\\*[\\s]+tableExport.jquery.plugin[\\s]+Version (?P<v>§)', '/\\*![\\s]+\\* TableExport.js v(?P<v>§)'), ()),
        ('tinymce', ('// (?P<v>§) \\([0-9\\-]+\\)[\n\r]+.{0,1200}l=.tinymce/geom/Rect.', '/\\*\\*[\\s]*\\* TinyMCE version (?P<v>§)'), ()),
        ('ua-parser-js', ('/\\* UAParser.js v(?P<v>§)', '/\\*[*!](?:@license)?[\\s]+\\* UAParser.js v(?P<v>§)', '// UAParser.js v(?P<v>§)', '.\\.VERSION="(?P<v>§)",.\\.BROWSER=\\{NAME:.,MAJOR:"major",VERSION:.\\},.\\.CPU=\\{ARCHITECTURE:', '.\\.VERSION="(?P<v>§)",.\\.BROWSER=.\\(\\[[^\\]]{1,20}\\]\\),.\\.CPU=', 'LIBVERSION="(?P<v>§)",EMPTY="",UNKNOWN="\\?",FUNC_TYPE="function",UNDEF_TYPE="undefined"', '.="(?P<v>§)",.="",.="\\?",.="function",.="undefined",.="object",(.="string",)?.="major",.="model",.="name",.="type",.="vendor"'), ()),
        ('underscore', ('//[\\s]*Underscore.js (?P<v>§)', '// *Underscore\\.js[\\s\\S]{1,2500}_\\.VERSION *= *[\'"](?P<v>§)[\'"]'), ()),
        ('video.js', ('\\* Video\\.js (?P<v>§)', '\\.videojs=[a-zA-Z]\\(\\)\\}\\(this,function\\(\\)\\{var [a-zA-Z]=["\'](?P<v>§)["\']', '["\']The element or ID supplied is not valid. \\(videojs\\)["\']\\)[\\s\\S]{100,400}var (?:[a-zA-Z]{1,2},)?[a-zA-Z]{1,2}=["\'](?P<v>§)["\']'), ('video\\.js[-.](?P<v>§)(\\.min)?\\.js',)),
        ('vue', ('/\\*!\\n \\* Vue.js v(?P<v>§)', '/\\*\\*?!?\\n ?\\* vue v(?P<v>§)', "Vue.version = '(?P<v>§)';", "'(?P<v>§)'[^\\n]{0,8000}Vue compiler", '\\* Original file: /npm/vue@(?P<v>§)/dist/vue.(global|common).js', 'const version[ ]*=[ ]*"(?P<v>§)";[\\s]*/\\*\\*[\\s]*\\* SSR utils for \\\\@vue/server-renderer', '\\.__vue_app__=.{0,8000}?const [a-z]+="(?P<v>§)",', 'let [A-Za-z]+="(?P<v>§)",..="undefined"!=typeof window&&window.trustedTypes;if\\(..\\)try\\{.=..\\.createPolicy\\("vue",', 'isCustomElement.{1,5}?compilerOptions.{0,500}exposeProxy.{0,700}"(?P<v>§)"', '"(?P<v>§)"[\\s\\S]{0,150}\\.createPolicy\\("vue"', 'devtoolsFormatters[\\s\\S]{50,180}"(?P<v>§)"[\\s\\S]{50,180}\\.createElement\\("template"\\)'), ('vue-(?P<v>§)(\\.min)?\\.js',)),
        ('zrender', ("ssrDataGetter = getter;[\\s]+\\}[\\s]+var version = '(?P<v>§)';[\\s]+", "painterCtors\\[name\\] = Ctor;[\\s]+\\}[\\s]+var version = '(?P<v>§)';[\\s]+", '.\\.util=[a-zA-Z_]+,.\\.vector=[a-zA-Z_]+,.\\.version=[\'"](?P<v>§)[\'"],Object'), ('zrender[-.](?P<v>§)(.min)?.js',)),
        ('cordova-android', ("PLATFORM_VERSION_BUILD_LABEL\\s*=\\s*'(?P<v>§)'",), ()),  # Cordova 框架本身 (cordova.js)
    )

    # 打包工具內嵌的 package.json (name、version、description 連在一起) -> 通用的 npm 套件辨識
    # 使用: lab_016 (透過 js_libraries)
    LIB_JS_PACKAGE_RE = re.compile(r'"?name"?:"(?P<n>@?[a-z0-9][a-z0-9._-]*(?:/[a-z0-9._-]+)?)","?version"?:"(?P<v>[0-9][0-9.a-z_\-]+)","?description"?:')

    # 掃描的網頁檔 (Hybrid App 的 assets、React Native 的 bundle); 單檔與總量上限避免掃太久
    # 使用: lab_016 (透過 js_libraries)
    LIB_JS_SUFFIXES = ('.js', '.mjs', '.html', '.htm', '.bundle')
    LIB_JS_MAX_FILE = 8 * 1024 * 1024
    LIB_JS_MAX_TOTAL = 80 * 1024 * 1024

    # 網頁檔有一半以上是二進位 (加密) 且至少這麼多個 -> 網頁程式碼被加密, 函式庫無法辨識
    # 16 個對照 APK 實測 (2026-10-18): 元大 assets/www 的 920 個 .js 都是加密內容
    # 使用: lab_016
    LIB_JS_ENCRYPTED_MIN = 5

    # OSV 查得到的套件生態系 (Java、網頁、Flutter、.NET)
    # 使用: lab_016
    LIB_OSV_ECOSYSTEMS = ('Maven', 'npm', 'Pub', 'NuGet')

    # class 被搬到短套件 (o.a、a.b.c) 達 OBF_REPACKAGED_MIN 個且佔全部 class 這個比例以上 -> 函式庫的套件名被混淆掉, 無法辨識
    # 16 個對照 APK 實測 (2026-10-16): tusky 87%、notes 84%、gallery 62%、兆豐 7% (函式庫被搬走); 台銀 0.9% (預先混淆的廠商 SDK)
    # 使用: lab_016 (透過 lib_code_hidden)
    LIB_REPACKAGED_RATIO = 0.03

    # 沒有版本字串的 .so: 自己定義 (export) 這些函式 -> 內含該函式庫; (名稱, 函式名稱, NVD CPE vendor:product)
    # 只算 .so 自己定義的函式 (呼叫系統函式庫的不算); CPE 名稱已用 NVD 查證
    # 使用: lab_016 (透過 native_products)
    LIB_NATIVE_SYMBOLS = (
        ('openssl', (b'SSL_CTX_new', b'OPENSSL_init_ssl'), 'openssl:openssl'),
        ('sqlcipher', (b'sqlcipher_export',), 'zetetic:sqlcipher'),
        ('sqlite', (b'sqlite3_open_v2',), 'sqlite:sqlite'),
        ('libjpeg-turbo', (b'tjDecompress2', b'jpeg_read_header'), 'libjpeg-turbo:libjpeg-turbo'),
        ('giflib', (b'DGifOpen',), 'giflib_project:giflib'),
        ('freetype', (b'FT_Init_FreeType',), 'freetype:freetype'),
        ('harfbuzz', (b'hb_buffer_create',), 'harfbuzz_project:harfbuzz'),
        ('libxml2', (b'xmlReadMemory', b'xmlParseMemory'), 'xmlsoft:libxml2'),
        ('expat', (b'XML_ParserCreate',), 'libexpat_project:libexpat'),
        ('libcurl', (b'curl_easy_perform',), 'haxx:libcurl'),
        ('ffmpeg', (b'avcodec_open2', b'avformat_open_input'), 'ffmpeg:ffmpeg'),
        ('libvpx', (b'vpx_codec_decode',), 'webmproject:libvpx'),
        ('opus', (b'opus_decode',), 'opus-codec:opus'),
        ('libtiff', (b'TIFFOpen',), 'libtiff:libtiff'),
        ('mbedtls', (b'mbedtls_ssl_init',), 'arm:mbed_tls'),
        ('wolfssl', (b'wolfSSL_Init',), 'wolfssl:wolfssl'),
        ('zstd', (b'ZSTD_decompress',), 'facebook:zstandard'),
        ('brotli', (b'BrotliDecoderDecompress',), 'google:brotli'),
        ('libarchive', (b'archive_read_new',), 'libarchive:libarchive'),
        ('tensorflow-lite', (b'TfLiteInterpreterCreate',), 'google:tensorflow'),
        ('libpng', (b'png_create_read_struct',), 'libpng:libpng'),
        ('zlib', (b'inflateInit2_',), 'zlib:zlib'))

    # .so 檔名對不到上面的函式庫時, 用檔名到 NVD 產品清單 (CPE) 找同名產品; 這些是 Android / Jetpack / 框架自己的 .so, 不查
    # 使用: lab_016 (透過 native_products)
    LIB_NATIVE_SKIP_RE = re.compile(r'^lib(?:androidx\.|datastore|surface_util|image_processing_util|conscrypt|c\+\+_shared|'
                                    r'flutter|app$|reactnative|hermes|jsc|fbjni|unity|il2cpp|main$|monodroid|mono|xamarin|'
                                    r'sentry|crashlytics|tensorflowlite_jni|realm|mmkv|bugly|.*_jni$)')
    LIB_MAX_NVD_NAME_LOOKUPS = 6

    # 沒有版本記錄、也不在 LIB_DEX_SIGNATURES 的 Java 函式庫: 用類別名稱到 Maven Central 反查; 這些不查
    # 使用: lab_016 (透過 maven_lookup_classes)
    LIB_MAVEN_SKIP_PREFIXES = ('Landroid/', 'Landroidx/', 'Lcom/google/', 'Lkotlin/', 'Lkotlinx/', 'Ljava/', 'Ljavax/', 'Lj$/',
                               'Ldalvik/', 'Lorg/w3c/', 'Lorg/xml/', 'Lorg/json/', 'Lsun/', 'Lcom/android/', 'Lorg/intellij/',
                               'Lorg/jetbrains/annotations/', 'Lorg/apache/http/')
    LIB_MAX_MAVEN_LOOKUPS = 60

    # Maven Central 搜尋服務回應不穩 (同一查詢 0.7 秒到逾時都有): 整段最多 30 秒、每次 6 秒, 不影響後面的 OSV 查詢;
    # 查不到的套件當作認不出 (結果記在 maven_unresolved), 成功的結果有快取, 之後掃描會補齊
    # 使用: lab_016
    LIB_MAVEN_SECONDS = 30
    LIB_MAVEN_TIMEOUT = 6

    # Maven Central 反查: 很多組織共用的第 2 層套件名, groupId 要再比對第 3 層
    # 使用: lab_016 (透過 maven_pick)
    LIB_MAVEN_GENERIC = {'apache', 'github', 'google', 'eclipse', 'jetbrains', 'android', 'microsoft', 'amazon', 'amazonaws',
                         'facebook', 'alibaba', 'tencent', 'baidu', 'huawei', 'sun', 'oracle', 'ibm', 'springframework',
                         'mozilla', 'yahoo', 'twitter', 'netflix', 'linkedin', 'uber', 'square', 'squareup'}

    # Maven Central 反查結果存 30 天
    # 使用: lab_016
    LIB_MAVEN_CACHE = '/tmp/cmaa_lab016_maven_cache.json'
    LIB_MAVEN_CACHE_DAYS = 30

    # BouncyCastle 1.71 起改名為 bcprov-jdk18on
    # 使用: lab_016 (透過 dex_libraries)
    LIB_BC_JDK18_FROM = (1, 71)

    def library_inventory(apk):
        """從 APK 檔案辨識函式庫名稱與版本: META-INF/*.version、根目錄 *.properties、pom.properties、.so 版本字串;
        另回傳 libwebp CVE-2023-4863 特徵比對結果
        回傳 (components {(ecosystem, name, version): [檔案]}, webp [{file, status}], unidentified [{file, reason}])
        使用: lab_016"""
        components, webp, unidentified = {}, [], []
        def add(ecosystem, name, version, path):
            components.setdefault((ecosystem, name, version), []).append(path)
        try:
            files = [f for f in apk.get_files() if isinstance(f, str)]
        except Exception:
            return components, webp, [{'file': '', 'reason': 'APK file list unavailable'}]
        for path in files:
            is_meta = re.fullmatch(r'META-INF/[^/]+\.version', path) or re.fullmatch(r'[^/]+\.properties', path) \
                or re.fullmatch(r'META-INF/maven/[^/]+/[^/]+/pom\.properties', path)
            if not is_meta and not path.endswith('.so'):
                continue
            try:
                raw = apk.get_file(path)
            except Exception:
                raw = None
            if not isinstance(raw, bytes):
                unidentified.append({'file': path, 'reason': 'unreadable'})
                continue
            if path.endswith('.so'):
                found = False
                for name, pattern, _, only in LIB_NATIVE_BANNERS:
                    if only and not path.endswith('/' + only):
                        continue
                    versions = set(v.decode('ascii') for v in pattern.findall(raw))
                    if len(versions) == 1:
                        add('native', name, versions.pop(), path)
                        found = True
                    elif versions:
                        unidentified.append({'file': path, 'reason': name + ' has several version strings'})
                if b'WebPCopyPlane' in raw or b'VP8LBuildHuffmanTable' in raw:
                    if b'VP8LHuffmanTablesAllocate' in raw:
                        webp.append({'file': path, 'status': 'patched'})
                    elif b'VP8LBuildHuffmanTable' in raw:
                        webp.append({'file': path, 'status': 'vulnerable'})
                    elif not found:
                        unidentified.append({'file': path, 'reason': 'libwebp found, version and patch state unknown'})
                    found = True
                if not found:
                    unidentified.append({'file': path, 'reason': 'native library version not found'})
                continue
            if len(raw) > 65536:
                continue
            text = raw.decode('utf-8', 'replace')
            if path.endswith('pom.properties'):
                props = dict(re.findall(r'(?m)^\s*(groupId|artifactId|version)\s*[=:]\s*(\S+)', text))
                if props.get('groupId') and props.get('artifactId') and LIB_VERSION_RE.fullmatch(props.get('version', '')):
                    add('Maven', props['groupId'] + ':' + props['artifactId'], props['version'], path)
                else:
                    unidentified.append({'file': path, 'reason': 'version not written'})
            elif path.endswith('.version'):
                stem, version = path[9:-8], text.strip()
                coord = re.fullmatch(r'([a-z][\w-]*(?:\.[\w-]+)+)_([\w.-]+)', stem)
                if stem.startswith('kotlinx_'):
                    name = 'org.jetbrains.kotlinx:' + stem.replace('_', '-')
                elif coord:
                    name = coord.group(1) + ':' + coord.group(2)
                else:
                    unidentified.append({'file': path, 'reason': 'unknown library name'})
                    continue
                if LIB_VERSION_RE.fullmatch(version):
                    add('Maven', name, version, path)
                else:
                    unidentified.append({'file': path, 'reason': 'version not written'})
            else:
                props = dict(re.findall(r'(?m)^\s*(version|client)\s*=\s*(\S+)', text))
                if 'version' not in props:
                    continue  # 不是函式庫版本檔
                client = props.get('client', path[:-11])
                group = next((g for prefix, g in LIB_PROPERTIES_GROUPS if client.startswith(prefix)), None)
                if group and LIB_VERSION_RE.fullmatch(props['version']):
                    add('Maven', group + ':' + client, props['version'], path)
                else:
                    unidentified.append({'file': path, 'reason': 'unknown library name'})
        return components, webp, unidentified

    def lib_is_binary(raw):
        """檔案開頭 2 KB 有超過 5% 的控制字元 -> 不是文字 (加密或壓縮)
        使用: lab_016 (透過 js_libraries)"""
        head = raw[:2048]
        return bool(head) and sum(1 for b in head if b < 9 or 13 < b < 32) > len(head) * 0.05

    def js_libraries(apk, files):
        """assets 裡的網頁檔、React Native bundle -> 用 LIB_JS_SIGNATURES 與內嵌 package.json 辨識 npm 套件與版本
        回傳 (found {(npm 套件, 版本): [檔案]}, 加密檔數, 網頁檔總數)
        使用: lab_016"""
        version_re = r'[0-9][0-9.a-z_\-]+'
        rules = [(name, [re.compile(p.replace('§', version_re)) for p in content],
                  [re.compile(p.replace('§', version_re)) for p in names]) for name, content, names in LIB_JS_SIGNATURES]
        found, encrypted, total, budget = {}, 0, 0, LIB_JS_MAX_TOTAL
        def add(name, version, path):
            version = version.rstrip('.-_')
            if re.fullmatch(r'[0-9]+(?:\.[0-9]+){1,3}(?:[-.][0-9A-Za-z.]+)?', version):
                found.setdefault((name, version), []).append(path)
        for path in files:
            if not path.startswith('assets/') or not path.endswith(LIB_JS_SUFFIXES):
                continue
            total += 1
            try:
                raw = apk.get_file(path)
            except Exception:
                continue
            if not isinstance(raw, bytes) or len(raw) > LIB_JS_MAX_FILE or budget <= 0:
                continue
            if lib_is_binary(raw):
                encrypted += 1
                continue
            budget -= len(raw)
            text, base = raw.decode('utf-8', 'replace'), path.rsplit('/', 1)[-1]
            for name, content, names in rules:
                m = next((m for m in (r.search(base) for r in names) if m), None) or \
                    next((m for m in (r.search(text) for r in content) if m), None)
                if m:
                    add(name, m.group('v'), path)
            for m in LIB_JS_PACKAGE_RE.finditer(text):
                add(m.group('n'), m.group('v'), path)
        return found, encrypted, total

    def flutter_packages(apk, files):
        """Flutter 的 libapp.so 裡 package:名稱/ 字串 -> Dart (Pub) 套件名稱 (編譯後沒有版本)
        使用: lab_016"""
        names = set()
        for path in files:
            if path.startswith('lib/') and path.endswith('/libapp.so'):
                try:
                    raw = apk.get_file(path)
                except Exception:
                    continue
                if isinstance(raw, bytes):
                    names.update(n.decode('ascii') for n in re.findall(rb'package:([a-z][a-z0-9_]*)/', raw))
        return sorted(names - {'flutter', 'flutter_test', 'dart'})[:200]

    def dotnet_product_version(raw):
        """.NET 組件 (PE) 版本資源裡的 ProductVersion (去掉 +commit); 讀不到回傳 ''
        使用: lab_016 (透過 dotnet_libraries)"""
        key = 'ProductVersion'.encode('utf-16-le') + b'\x00\x00'
        start = raw.find(key)
        if start < 0:
            return ''
        start += len(key)
        start += (-start) % 4
        end = start
        while end + 1 < len(raw) and raw[end:end + 2] != b'\x00\x00' and end - start < 200:
            end += 2
        text = raw[start:end].decode('utf-16-le', 'replace').split('+')[0].strip()
        return text if re.fullmatch(r'[0-9]+(?:\.[0-9]+){1,3}(?:-[A-Za-z0-9.]+)?', text) else ''

    def dotnet_libraries(apk, files):
        """Xamarin / .NET App 的組件 (assemblies/*.dll) -> NuGet 套件名稱 (= 組件名稱) 與 ProductVersion
        壓縮 (XALZ) 或打包成 assembly store (.blob) 的讀不到, 回傳原因
        回傳 (found {(套件, 版本): [檔案]}, 讀不到的原因或 '')
        使用: lab_016"""
        found, unreadable = {}, 0
        stores = [p for p in files if p.endswith('.blob') or re.search(r'/libassemblies\.[^/]*\.blob\.so$', p)]
        for path in files:
            if not (path.startswith('assemblies/') and path.endswith('.dll')):
                continue
            try:
                raw = apk.get_file(path)
            except Exception:
                raw = None
            if not isinstance(raw, bytes) or raw[:4] == b'XALZ':
                unreadable += 1
                continue
            version = dotnet_product_version(raw)
            if version:
                found.setdefault((path.rsplit('/', 1)[-1][:-4], version), []).append(path)
        reason = ''
        if stores or unreadable:
            reason = ('.NET assemblies are compressed or packed into an assembly store (%d files), so their libraries '
                      'cannot be identified; needs manual review' % (len(stores) + unreadable))
        return found, reason

    def elf_defined_symbols(raw):
        """.so (ELF) 動態符號表裡自己定義的函式名稱 (st_shndx != 0); 不是 ELF 或讀不到回傳空集合
        使用: lab_016 (透過 native_products)"""
        import struct
        names = set()
        try:
            if raw[:4] != b'\x7fELF':
                return names
            is64, endian = raw[4] == 2, '<' if raw[5] == 1 else '>'
            if is64:
                shoff, = struct.unpack_from(endian + 'Q', raw, 0x28)
                shentsize, shnum = struct.unpack_from(endian + 'HH', raw, 0x3A)
            else:
                shoff, = struct.unpack_from(endian + 'I', raw, 0x20)
                shentsize, shnum = struct.unpack_from(endian + 'HH', raw, 0x2E)
            sections = []
            for i in range(shnum):
                off = shoff + i * shentsize
                if is64:
                    _, stype, _, _, offset, size, link, _, _, entsize = struct.unpack_from(endian + 'IIQQQQIIQQ', raw, off)
                else:
                    _, stype, _, _, offset, size, link, _, _, entsize = struct.unpack_from(endian + 'IIIIIIIIII', raw, off)
                sections.append((stype, offset, size, link, entsize))
            for stype, offset, size, link, entsize in sections:
                if stype != 11 or not entsize:          # SHT_DYNSYM
                    continue
                _, str_off, str_size, _, _ = sections[link]
                for j in range(size // entsize):
                    base = offset + j * entsize
                    if is64:
                        name, _, _, shndx = struct.unpack_from(endian + 'IBBH', raw, base)
                    else:
                        name, = struct.unpack_from(endian + 'I', raw, base)
                        shndx, = struct.unpack_from(endian + 'H', raw, base + 14)
                    if shndx and name < str_size:
                        end = raw.find(b'\x00', str_off + name)
                        names.add(raw[str_off + name:end])
        except Exception:
            return names
        return names

    def native_products(apk, unidentified, known):
        """沒有版本字串的 .so -> 認得出的函式庫 {名稱: (CPE vendor:product 或 None, [檔案])};
        先用自己定義的函式名稱 (LIB_NATIVE_SYMBOLS), 對不到的留檔名 (CPE 為 None, 之後用 NVD 產品清單查)
        known: 已讀到版本的原生函式庫名稱 (略過)
        使用: lab_016"""
        found = {}
        for item in unidentified:
            path = item.get('file', '')
            if item.get('reason') != 'native library version not found' or not path.endswith('.so'):
                continue
            try:
                raw = apk.get_file(path)
            except Exception:
                continue
            if not isinstance(raw, bytes):
                continue
            symbols = elf_defined_symbols(raw)
            boring = b'BoringSSL' in raw                 # Conscrypt 等內含 BoringSSL, OpenSSL 的 CVE 不適用
            hits = [(n, c) for n, syms, c in LIB_NATIVE_SYMBOLS if any(x in symbols for x in syms)
                    and not (n == 'openssl' and boring)]
            for name, cpe in hits:
                if name not in known:
                    found.setdefault(name, (cpe, []))[1].append(path)
            if hits:
                continue
            stem = path.rsplit('/', 1)[-1][:-3]
            if not LIB_NATIVE_SKIP_RE.match(stem):
                name = re.sub(r'([-_](android|jni|shared|static))+$', '', stem)
                found.setdefault('?' + name, (None, []))[1].append(path)
        return found

    def buildconfig_versions(dexes, own_prefixes):
        """函式庫自己的 BuildConfig.VERSION_NAME -> {套件: 版本}; 只收 X.Y.Z 形式 (排除空值、預設的 1.0 / 1.0.0)
        Google / AndroidX 已有版本檔, App 自己的不算
        使用: lab_016"""
        found = {}
        for dex in dexes:
            try:
                classes = dex.get_classes()
            except Exception:
                continue
            for cls in classes:
                name = cls.get_name()
                if not name.endswith('/BuildConfig;') or name.startswith(('Lcom/google/', 'Landroidx/')) \
                        or (own_prefixes and name.startswith(own_prefixes)):
                    continue
                for field in cls.get_fields():
                    if field.get_name() != 'VERSION_NAME':
                        continue
                    try:
                        value = field.get_init_value()
                        value = value.get_value() if value is not None else None
                    except Exception:
                        value = None
                    if isinstance(value, str) and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?', value) \
                            and value not in ('1.0.0', '0.0.0', '0.0.1'):
                        found.setdefault(name[1:-len('/BuildConfig;')], set()).add(value)
        return {pkg: versions.pop() for pkg, versions in found.items() if len(versions) == 1}

    def react_native_version(dexes):
        """React Native 的 ReactNativeVersion 類別 (<clinit> 依序放 "major", 數字, "minor", 數字, "patch", 數字) -> 版本; 找不到回傳 ''
        使用: lab_016"""
        for dex in dexes:
            try:
                cls = dex.get_class('Lcom/facebook/react/modules/systeminfo/ReactNativeVersion;')
            except Exception:
                cls = None
            for method in (cls.get_methods() if cls is not None else []):
                if method.get_name() != '<clinit>':
                    continue
                parts, key = {}, None
                for ins in method.get_instructions():
                    op = ins.get_name()
                    if op.startswith('const-string') and hasattr(ins, 'get_string'):
                        key = ins.get_string() if ins.get_string() in ('major', 'minor', 'patch') else None
                    elif key and op.startswith('const') and not op.startswith('const-string'):
                        try:
                            parts[key] = int(ins.get_output().split(',')[-1].strip(), 0)
                        except ValueError:
                            pass
                        key = None
                if all(k in parts for k in ('major', 'minor', 'patch')):
                    return '%d.%d.%d' % (parts['major'], parts['minor'], parts['patch'])
        return ''

    def maven_lookup_classes(classes, own_prefixes, covered):
        """還沒辨識的 Java 函式庫套件 -> 每個套件挑一個代表類別 (之後到 Maven Central 反查) [(套件, 類別)]
        套件取前 3 層, 至少 3 個 class; 排除 App 自己、平台、已辨識 (covered)、混淆後的短套件
        使用: lab_016"""
        groups = {}
        for c in classes:
            if c.startswith(LIB_MAVEN_SKIP_PREFIXES) or (own_prefixes and c.startswith(own_prefixes)) \
                    or c.startswith(covered) or is_repackaged_class(c):
                continue
            parts = c[1:-1].split('/')
            if len(parts) < 2 or any(len(p) <= 1 for p in parts[:-1]):
                continue
            groups.setdefault('/'.join(parts[:min(3, len(parts) - 1)]), []).append(c)
        out = []
        for pkg, members in sorted(groups.items()):
            names = sorted(m for m in members if '$' not in m and len(m.rsplit('/', 1)[-1]) > 5
                           and not re.search(r'(Exception|Error);$', m))
            if len(members) >= 3 and names:
                out.append((pkg, names[0][1:-1].replace('/', '.')))
        return out[:LIB_MAX_MAVEN_LOOKUPS]

    def maven_pick(package, candidates):
        """Maven Central 查到的候選 [(groupId, artifactId, 次數)] 裡, 挑 groupId 跟 Java 套件名稱一致的 (排除別人重新打包發佈的)
        一致: 套件第 2 層出現在 groupId; 第 2 層是共用名稱 (apache 等) 時第 3 層也要出現在 groupId 或 artifactId;
        只有 1 層的套件 (okio、okhttp3) 要出現在 groupId 或 artifactId; 沒有一致的回傳 ''
        使用: lab_016"""
        parts = package.split('/')
        def ok(g, a):
            g, a = g.lower(), a.lower()
            if len(parts) == 1:
                return parts[0] in g or parts[0] in a
            if parts[1] not in g:
                return False
            if parts[1] in LIB_MAVEN_GENERIC and len(parts) >= 3:
                return parts[2] in g or parts[2] in a
            return True
        good = [(g, a, n) for g, a, n in candidates if ok(g, a)]
        if not good:
            return ''
        g, a, _ = max(good, key=lambda x: (x[2], -len(x[1])))
        return g + ':' + a

    def lib_json_cache_load(path, days):
        """讀快取 (超過 days 天的丟掉); 讀不到回傳空 dict
        使用: lab_016"""
        try:
            with open(path, encoding='utf-8') as fh:
                data = json.load(fh)
        except Exception:
            return {}
        limit = time.time() - days * 86400
        return {k: v for k, v in data.items() if isinstance(v, dict) and v.get('time', 0) > limit} if isinstance(data, dict) else {}

    def lib_json_cache_save(path, cache):
        """寫回快取 (先寫暫存檔再改名, 失敗不影響檢測)
        使用: lab_016"""
        try:
            with open(path + '.tmp', 'w', encoding='utf-8') as fh:
                json.dump(cache, fh)
            os.replace(path + '.tmp', path)
        except Exception:
            pass

    def lib_nvd_cache_load():
        """讀 NVD 分數快取, 丟掉超過 LIB_NVD_CACHE_DAYS 的; 讀不到回傳空 dict
        使用: lab_016"""
        try:
            with open(LIB_NVD_CACHE, encoding='utf-8') as fh:
                data = json.load(fh)
        except Exception:
            return {}
        limit = time.time() - LIB_NVD_CACHE_DAYS * 86400
        return {k: v for k, v in data.items() if isinstance(v, dict) and v.get('time', 0) > limit} if isinstance(data, dict) else {}

    def lib_nvd_cache_save(cache):
        """寫回 NVD 分數快取 (先寫暫存檔再改名, 寫入失敗不影響檢測)
        使用: lab_016"""
        try:
            tmp = LIB_NVD_CACHE + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as fh:
                json.dump(cache, fh)
            os.replace(tmp, LIB_NVD_CACHE)
        except Exception:
            pass

    def lib_short_name(name):
        """報告顯示用的函式庫名稱: Maven 只留 artifact (com.google.code.gson:gson -> gson)
        使用: lab_016"""
        return ' / '.join(n.split(':')[-1] for n in name.split(' / '))

    def lib_version_key(version):
        """版本字串 -> 可比較的數字 tuple (只取開頭的數字段)
        使用: lab_016"""
        return tuple(int(x) for x in re.findall(r'[0-9]+', re.split(r'[-+]', version or '0')[0])[:4]) or (0,)

    def dex_class_names(dexes):
        """所有 DEX 的 class 名稱
        使用: lab_016"""
        classes = set()
        for dex in dexes:
            try:
                classes.update(c.get_name() for c in dex.get_classes())
            except Exception:
                continue
        return classes

    def lib_code_hidden(apk, classes):
        """程式碼看不到 (加殼) 或 class 被搬到短套件 (混淆) 時回傳原因, 此時程式碼裡的函式庫無法辨識; 看得到回傳 ''
        使用: lab_016"""
        prefixes = app_own_prefixes(apk)
        own = sum(1 for c in classes if c.startswith(prefixes)) if prefixes else 0
        moved = sum(1 for c in classes if is_repackaged_class(c))
        if own < OBF_MIN_CLASSES and moved < OBF_REPACKAGED_MIN:
            return 'app code not visible (packed?), so libraries inside the code cannot be identified; an unpacked APK is needed'
        if moved >= OBF_REPACKAGED_MIN and moved >= LIB_REPACKAGED_RATIO * len(classes):
            return ('obfuscation moved %d of %d classes into short packages (such as o.a), so libraries inside them cannot be '
                    'identified; an APK without obfuscation is needed' % (moved, len(classes)))
        return ''

    def dex_libraries(dexes, known, classes):
        """從 DEX 類別辨識 LIB_DEX_SIGNATURES 的函式庫, 盡量從字串取得版本; known 是版本檔已辨識到的 Maven 名稱 (略過)
        回傳 [{names, version, floor, evidence}] (version 讀不到為 '')
        使用: lab_016"""
        pool = None
        def class_strings(name):
            out = set()
            for dex in dexes:
                cls = dex.get_class(name)
                for m in (cls.get_methods() if cls is not None else []):
                    for ins in m.get_instructions():
                        if ins.get_name().startswith('const-string') and hasattr(ins, 'get_string'):
                            out.add(ins.get_string())
            return out
        found = []
        for names, markers, source, floors in LIB_DEX_SIGNATURES:
            if any(n in known for n in names):
                continue
            hit = next((c for m in markers for c in ([m] if m.endswith(';') and m in classes else
                        sorted(c for c in classes if m.endswith('/') and c.startswith(m)
                               and not re.search(r'(Exception|Error)[;$]', c)))), None)
            if not hit:
                continue
            versions = set()
            if source and source[0] == 'class':
                versions = set(v for v in class_strings(source[1]) if LIB_VERSION_RE.fullmatch(v))
            elif source:
                if pool is None:
                    pool = []
                    for dex in dexes:
                        try:
                            pool.extend(dex.get_strings())
                        except Exception:
                            continue
                versions = set(m for s in pool if isinstance(s, str) and len(s) < 200 for m in source[1].findall(s))
            version = versions.pop() if len(versions) == 1 else ''
            if version and names[0].startswith('org.bouncycastle:'):
                names = (names[1] if lib_version_key(version) >= LIB_BC_JDK18_FROM else names[0],)
            floor = max((v for c, v in floors if c in classes), key=lib_version_key, default='')
            found.append({'names': names, 'version': version, 'floor': floor, 'evidence': hit})
        return found

    def osv_ranges(vuln, name):
        """OSV 記錄裡某套件的受影響版本範圍 -> (顯示文字清單, 上限清單 [(版本, 是否包含)]; 上限 None 表示沒有修補版)
        使用: lab_016"""
        texts, uppers = [], []
        for aff in vuln.get('affected', []):
            if not isinstance(aff, dict) or aff.get('package', {}).get('name') != name:
                continue
            for rng in aff.get('ranges', []):
                start = None
                for ev in rng.get('events', []) if isinstance(rng, dict) else []:
                    if 'introduced' in ev:
                        start = ev['introduced']
                    elif ('fixed' in ev or 'last_affected' in ev) and start is not None:
                        end, incl = (ev['fixed'], False) if 'fixed' in ev else (ev['last_affected'], True)
                        low = '' if start in ('0', '') else start + ' to '
                        texts.append('%s%s%s' % (low, '' if incl else '< ', end))
                        uppers.append((end, incl))
                        start = None
                if start is not None:
                    texts.append('%s and later' % start)
                    uppers.append((None, True))
            if not aff.get('ranges') and aff.get('versions'):
                texts.append(', '.join(aff['versions'][:3]))
                uppers.extend((v, True) for v in aff['versions'])
        return texts, uppers

    def cvss3_base_score(vector):
        """依 CVSS v3.0 / v3.1 向量計算 base score, 回傳 (版本, 分數); 不是 v3 向量回傳 (None, None)
        使用: lab_016"""
        m = re.fullmatch(r'CVSS:(3\.[01])/(.+)', vector or '')
        if not m:
            return None, None
        metrics = dict(part.split(':', 1) for part in m.group(2).split('/') if ':' in part)
        try:
            scope = metrics['S']
            av = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}[metrics['AV']]
            ac = {'L': 0.77, 'H': 0.44}[metrics['AC']]
            pr = ({'N': 0.85, 'L': 0.62, 'H': 0.27} if scope == 'U' else {'N': 0.85, 'L': 0.68, 'H': 0.5})[metrics['PR']]
            ui = {'N': 0.85, 'R': 0.62}[metrics['UI']]
            cia = [{'H': 0.56, 'L': 0.22, 'N': 0}[metrics[k]] for k in ('C', 'I', 'A')]
        except KeyError:
            return None, None
        iss = 1 - (1 - cia[0]) * (1 - cia[1]) * (1 - cia[2])
        impact = 6.42 * iss if scope == 'U' else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        if impact <= 0:
            return m.group(1), 0.0
        total = impact + 8.22 * av * ac * pr * ui
        total = min(total if scope == 'U' else 1.08 * total, 10)
        if m.group(1) == '3.0':
            return '3.0', math.ceil(total * 10) / 10
        n = int(round(total * 100000))
        return '3.1', n / 100000.0 if n % 10000 == 0 else (n // 10000 + 1) / 10.0

    def osv_fixed_version(vuln, name, version):
        """OSV 記錄裡, 涵蓋這個版本的範圍的修補版本; 找不到 (沒有修補版或範圍不明) 回傳 ''
        使用: lab_016"""
        key = lib_version_key(version)
        for aff in vuln.get('affected', []):
            if not isinstance(aff, dict) or aff.get('package', {}).get('name') != name:
                continue
            for rng in aff.get('ranges', []):
                start = None
                for ev in rng.get('events', []) if isinstance(rng, dict) else []:
                    if 'introduced' in ev:
                        start = ev['introduced']
                    elif 'fixed' in ev and start is not None:
                        if lib_version_key(start) <= key < lib_version_key(ev['fixed']):
                            return ev['fixed']
                        start = None
        return ''

    def cvss30_score(vector):
        """MAS 備註用 CVSS v3.0 分數: v3.1 向量的評分項目與 v3.0 相同, 改用 v3.0 公式重算; 回傳 ('3.0', 分數) 或 (None, None)
        (2019 年後的 CVE 多半只有 v3.1 分數)
        使用: lab_016"""
        m = re.fullmatch(r'CVSS:3\.[01]/(.+)', vector or '')
        return cvss3_base_score('CVSS:3.0/' + m.group(1)) if m else (None, None)

    def nvd_cvss3(record):
        """從 NVD CVE 記錄取 CVSS v3.0 分數: 先 v3.0 再 v3.1 (以 v3.0 公式重算), 同版本優先 NVD (Primary);
        回傳 (版本, 分數, 向量) 或 None
        使用: lab_016"""
        for key in ('cvssMetricV30', 'cvssMetricV31'):
            rows = [r for r in record.get('metrics', {}).get(key, []) if isinstance(r, dict)]
            rows.sort(key=lambda r: r.get('type') != 'Primary')
            for row in rows:
                data = row.get('cvssData', {})
                version, score = cvss30_score(data.get('vectorString', ''))
                if version:
                    return version, score, data.get('vectorString', '')
        return None

    def lib_http_json(url, payload=None, timeout=10):
        """查 OSV / NVD (只允許這兩個 API, 不跟隨轉址, 回應上限 4 MB), 回傳 JSON dict
        使用: lab_016"""
        if not url.startswith(('https://api.osv.dev/v1/', 'https://services.nvd.nist.gov/rest/json/cves/2.0?',
                               'https://services.nvd.nist.gov/rest/json/cpes/2.0?', 'https://search.maven.org/solrsearch/select?')):
            raise ValueError('unapproved lookup URL')
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args):
                raise ValueError('redirect refused')
        headers = {'Content-Type': 'application/json', 'User-Agent': 'CMAA-lab016/2'}
        if url.startswith('https://services.nvd.nist.gov/') and os.environ.get('NVD_API_KEY'):
            headers['apiKey'] = os.environ['NVD_API_KEY']
        data = None if payload is None else json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(url, data=data, headers=headers)
        with urllib.request.build_opener(NoRedirect).open(req, timeout=timeout) as resp:
            raw = resp.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError('response too large')
        result = json.loads(raw.decode('utf-8'))
        if not isinstance(result, dict):
            raise ValueError('invalid response')
        return result

    def library_vuln_result(apk, dexes=None, http=None):
        """lab_016 主流程: 辨識函式庫 (版本檔 + DEX 類別) -> OSV 批次查 Maven 套件 / NVD CPE 查原生函式庫 -> 留下有 CVE 且 CVSS v3 >= 7 的;
        讀不到版本的函式庫查所有版本, 有 CVSS >= 7 的漏洞版本就列入 review
        回傳 dict (verdict WARNING / NOT_EVALUATED / PASS、findings、components、unidentified、review)
        使用: lab_016"""
        http = http or lib_http_json
        deadline = time.monotonic() + LIB_MAX_SECONDS
        def timeout():
            left = deadline - time.monotonic()
            if left <= 1:
                raise ValueError('time limit reached')
            return min(15, left)
        inventory, webp, unidentified = library_inventory(apk)
        components = [{'ecosystem': e, 'name': n, 'version': v, 'files': sorted(set(f))[:3],
                       'cves': [], 'status': 'ok', 'note': ''} for (e, n, v), f in sorted(inventory.items())]
        known = set(c['name'] for c in components if c['ecosystem'] == 'Maven')
        maven_unresolved = []
        dexes = [x for x in (dexes or []) if x is not None]
        classes = dex_class_names(dexes)
        hidden = lib_code_hidden(apk, classes) if dexes else ''
        for lib in dex_libraries(dexes, known, classes):
            components.append({'ecosystem': 'Maven', 'name': ' / '.join(lib['names']), 'query_names': list(lib['names']),
                               'version': lib['version'], 'files': ['classes.dex: ' + lib['evidence']], 'cves': [],
                               'status': 'ok', 'note': 'identified from code', 'floor': lib['floor'], 'possible': []})
        findings, review = [], [hidden] if hidden else []

        # 函式庫自己的 BuildConfig.VERSION_NAME: 補上讀不到版本的函式庫 (同一套件或其子套件只有一個版本才用)
        bc_versions = buildconfig_versions(dexes, app_own_prefixes(apk)) if dexes else {}
        def buildconfig_version_for(pkg):
            versions = {v for p, v in bc_versions.items() if p == pkg or p.startswith(pkg + '/')}
            return versions.pop() if len(versions) == 1 else ''
        for comp in components:
            if comp.get('note') == 'identified from code' and not comp['version'] and len(comp.get('query_names', [])) == 1:
                vendor_pkg = comp['files'][0].split(': ', 1)[-1][1:].rsplit('/', 1)[0]
                version = buildconfig_version_for(vendor_pkg)
                if version:
                    comp['version'], comp['note'] = version, 'identified from code; version from BuildConfig.VERSION_NAME'

        # React Native 框架本身 (ReactNativeVersion)
        rn = react_native_version(dexes) if dexes else ''
        if rn:
            components.append({'ecosystem': 'npm', 'name': 'react-native', 'version': rn,
                               'files': ['classes.dex: com.facebook.react.modules.systeminfo.ReactNativeVersion'],
                               'cves': [], 'status': 'ok', 'note': 'React Native framework'})

        # 清單外、沒有版本記錄的 Java 函式庫: 用類別名稱到 Maven Central 反查函式庫名稱 (之後查所有版本的漏洞)
        if dexes and not hidden:
            def vendor(m):
                parts = m[1:].split('/')
                keep = 3 if len(parts) > 2 and parts[1] in LIB_MAVEN_GENERIC else 2
                return 'L' + '/'.join(parts[:min(keep, len(parts) - 1)]) + '/'
            covered = tuple(vendor(m) for _, markers, _, _ in LIB_DEX_SIGNATURES for m in markers)
            lookups = maven_lookup_classes(classes, app_own_prefixes(apk), covered)
            maven_cache = lib_json_cache_load(LIB_MAVEN_CACHE, LIB_MAVEN_CACHE_DAYS)
            maven_deadline = time.monotonic() + LIB_MAVEN_SECONDS
            def maven_find(pkg, cls):
                # 快取存原始候選 (groupId, artifactId, 次數), 挑選規則改了不必重查
                if cls not in maven_cache:
                    left = maven_deadline - time.monotonic()
                    if left <= 1:
                        raise ValueError('Maven Central time budget used')
                    data = http('https://search.maven.org/solrsearch/select?' + urllib.parse.urlencode(
                        {'q': 'fc:' + cls, 'rows': 50, 'wt': 'json'}), None, min(LIB_MAVEN_TIMEOUT, left))
                    counts = {}
                    for doc in (data.get('response') or {}).get('docs') or []:
                        if doc.get('g') and doc.get('a'):
                            counts[(doc['g'], doc['a'])] = counts.get((doc['g'], doc['a']), 0) + 1
                    maven_cache[cls] = {'time': time.time(), 'cands': [[g, a, n] for (g, a), n in counts.items()]}
                return maven_pick(pkg, maven_cache[cls].get('cands', []))
            def maven_safe(item):
                try:
                    return maven_find(*item)
                except Exception:
                    return None
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                answers = list(pool.map(maven_safe, lookups))
            lib_json_cache_save(LIB_MAVEN_CACHE, maven_cache)
            maven_unresolved = [pkg.replace('/', '.') for (pkg, _), x in zip(lookups, answers) if x is None]
            added = set(known)
            for (pkg, cls), ga in zip(lookups, answers):
                if ga and ga not in added:
                    added.add(ga)
                    version = buildconfig_version_for(pkg)
                    components.append({'ecosystem': 'Maven', 'name': ga, 'query_names': [ga], 'version': version,
                                       'files': ['classes.dex: ' + pkg.replace('/', '.')], 'cves': [], 'status': 'ok',
                                       'note': 'identified from code (Maven Central)' +
                                               ('; version from BuildConfig.VERSION_NAME' if version else ''),
                                       'floor': '', 'possible': []})

        # 網頁 (assets 的 JavaScript、React Native bundle)、.NET 組件、Flutter 套件
        try:
            files = [f for f in apk.get_files() if isinstance(f, str)]
        except Exception:
            files = []
        js_found, js_encrypted, js_total = js_libraries(apk, files)
        dotnet_found, dotnet_reason = dotnet_libraries(apk, files)
        for (ecosystem, note), found in ((('npm', 'identified from web code'), js_found),
                                         (('NuGet', 'identified from .NET assemblies'), dotnet_found)):
            for (name, version), paths in sorted(found.items()):
                components.append({'ecosystem': ecosystem, 'name': name, 'version': version, 'files': sorted(set(paths))[:3],
                                   'cves': [], 'status': 'ok', 'note': note})
        for name in flutter_packages(apk, files):
            components.append({'ecosystem': 'Pub', 'name': name, 'query_names': [name], 'version': '', 'files': ['libapp.so'],
                               'cves': [], 'status': 'ok', 'note': 'identified from Flutter code', 'floor': '', 'possible': []})
        if js_encrypted >= LIB_JS_ENCRYPTED_MIN and js_encrypted * 2 >= js_total:
            review.append('web code in assets is encrypted (%d of %d files), so web libraries cannot be identified; '
                          'an unencrypted APK is needed' % (js_encrypted, js_total))
        if dotnet_reason:
            review.append(dotnet_reason)
        def unresolved(comp, note):
            comp['status'], comp['note'] = 'unresolved', note
            review.append('%s %s: %s' % (lib_short_name(comp['name']), comp['version'], note))
        def add_cve(comp, cve, version, score, vector, source, fixed=''):
            if any(c['id'] == cve for c in comp['cves']):
                return
            comp['cves'].append({'id': cve, 'cvss_version': version, 'score': score})
            if score >= LIB_CVSS_THRESHOLD:
                comp['status'] = 'vulnerable'
                findings.append({'library': comp['name'], 'version': comp['version'], 'ecosystem': comp['ecosystem'], 'cve': cve,
                                 'cvss_version': version, 'score': score, 'vector': vector, 'source': source,
                                 'fixed': fixed, 'files': comp['files']})

        # libwebp 特徵: 未修補 -> 直接列 CVE-2023-4863
        for item in webp:
            comp = {'ecosystem': 'native', 'name': 'libwebp (symbols)', 'version': item['status'],
                    'files': [item['file']], 'cves': [], 'status': 'ok', 'note': 'CVE-2023-4863 symbol check'}
            components.append(comp)
            if item['status'] == 'vulnerable':
                version, score = cvss30_score(LIB_WEBP_CVE['vector'])
                add_cve(comp, LIB_WEBP_CVE['cve'], version, score, LIB_WEBP_CVE['vector'],
                        'VP8LHuffmanTablesAllocate (added in fixed libwebp 1.3.2) missing', '1.3.2')
        # libwebp 在、但內部函式名稱被拿掉 (沒有版本字串): 看不出有沒有修補 -> 人工排查
        for item in unidentified:
            if item['reason'].startswith('libwebp found'):
                review.append('libwebp: version and patch state unknown; %s (CVSS v3.0 %s) affects versions < 1.3.2; '
                              'needs manual review' % (LIB_WEBP_CVE['cve'], cvss30_score(LIB_WEBP_CVE['vector'])[1]))

        # OSV 查得到的套件 (Maven、npm、Pub、NuGet): 批次查詢 (OSV 依版本比對), 再取漏洞明細的 CVE 編號與 CVSS v3 向量
        maven = [c for c in components if c['ecosystem'] in LIB_OSV_ECOSYSTEMS]
        nvd_left, nvd_times = [LIB_MAX_NVD_REQUESTS], []
        nvd_cache = {}
        def nvd_get(url):
            # NVD 沒有 API key 時 30 秒內最多 5 次: 第 6 次起等到最早那次滿 30 秒
            if nvd_left[0] <= 0:
                raise ValueError('NVD request limit reached')
            nvd_left[0] -= 1
            if len(nvd_times) >= 5:
                wait = 31 - (time.monotonic() - nvd_times[-5])
                if wait > 0:
                    if time.monotonic() + wait > deadline - 5:
                        raise ValueError('time limit reached')
                    time.sleep(wait)
            nvd_times.append(time.monotonic())
            return http(url, None, timeout())
        disk = lib_nvd_cache_load()
        def nvd_score(cve):
            if cve not in nvd_cache and cve in disk:
                nvd_cache[cve] = tuple(disk[cve]['score']) if disk[cve]['score'] else None
            if cve not in nvd_cache:
                data = nvd_get('https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=' + cve)
                rows = data.get('vulnerabilities', [])
                nvd_cache[cve] = nvd_cvss3(rows[0].get('cve', {})) if len(rows) == 1 else None
                disk[cve] = {'time': time.time(), 'score': nvd_cache[cve]}
            return nvd_cache[cve]
        # 讀不到版本的函式庫: OSV 不帶版本查全部漏洞, 有 CVSS >= 7、且可能涵蓋最低版本以上的, 記成 possible
        def add_possible(comp, name, vuln, cves, scored, severity=''):
            # 只有 v4 分數時, 以 GitHub 評為 HIGH / CRITICAL 當作可能 >= 7 (分數顯示 high)
            score = max(s[1] for s in scored) if scored else (None if severity in ('HIGH', 'CRITICAL') else 0)
            if score is not None and score < LIB_CVSS_THRESHOLD:
                return
            texts, uppers = osv_ranges(vuln, name)
            floor = lib_version_key(comp.get('floor'))
            if comp.get('floor') and uppers and not any(
                    end is None or lib_version_key(end) > floor or (incl and lib_version_key(end) == floor)
                    for end, incl in uppers):
                return  # 最低版本特徵已排除
            for cve in cves:
                if not any(p['cve'] == cve for p in comp['possible']):
                    comp['possible'].append({'cve': cve, 'score': score if score is not None else 'high', 'ranges': texts[:3]})
        pending = []
        if maven:
            queries = [(c, n) for c in maven for n in c.get('query_names', [c['name']])]
            try:
                batch = http('https://api.osv.dev/v1/querybatch', {'queries': [
                    dict({'package': {'ecosystem': c['ecosystem'], 'name': n}}, **({'version': c['version']} if c['version'] else {}))
                    for c, n in queries]}, timeout())
                results = batch.get('results')
                if not isinstance(results, list) or len(results) != len(queries):
                    raise ValueError('invalid OSV batch response')
            except Exception as exc:
                results = None
                for comp in maven:
                    unresolved(comp, 'OSV lookup failed (%s)' % str(exc)[:80])
            # 漏洞明細平行抓 (同一漏洞只抓一次), 失敗的存成例外
            wanted = []
            for res in results or []:
                for v in (res or {}).get('vulns', []):
                    if isinstance(v, dict) and isinstance(v.get('id'), str) and v['id'] not in wanted:
                        wanted.append(v['id'])
            def fetch(vid):
                try:
                    return http('https://api.osv.dev/v1/vulns/' + urllib.parse.quote(vid, safe=''), None, timeout())
                except Exception as exc:
                    return exc
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                details = dict(zip(wanted[:LIB_MAX_OSV_DETAILS], pool.map(fetch, wanted[:LIB_MAX_OSV_DETAILS])))
            for (comp, qname), res in zip(queries, results or []):
                ids = [v.get('id') for v in (res or {}).get('vulns', []) if isinstance(v, dict)]
                if (res or {}).get('next_page_token'):
                    unresolved(comp, 'OSV result incomplete')
                    continue
                for vid in ids:
                    try:
                        vuln = details.get(vid, ValueError('OSV detail limit reached'))
                        if isinstance(vuln, Exception) or not isinstance(vuln, dict):
                            raise vuln if isinstance(vuln, Exception) else ValueError('invalid OSV record')
                        if vuln.get('withdrawn'):
                            continue
                        cves = sorted(set(x for x in [vuln.get('id')] + vuln.get('aliases', [])
                                          if isinstance(x, str) and re.fullmatch(r'CVE-\d{4}-\d{4,}', x)))
                        if not cves:
                            continue  # 沒有 CVE 編號, 不在 MAS 判定範圍
                        scored = [cvss30_score(s.get('score')) + (s.get('score'),) for s in vuln.get('severity', [])
                                  if isinstance(s, dict) and s.get('type') == 'CVSS_V3']
                        scored = [s for s in scored if s[0]]
                        severity = (vuln.get('database_specific') or {}).get('severity', '')
                        if not comp['version']:
                            add_possible(comp, qname, vuln, cves, scored, severity)  # 版本不明: 不判 Failed, 也不查 NVD
                            continue
                        for cve in cves:
                            if scored:
                                version, score, vector = max(scored, key=lambda s: s[1])
                                source = 'OSV ' + vid
                            else:
                                pending.append((comp, qname, vuln, cve, severity))  # 沒有 v3 分數: 之後用 NVD 補
                                continue
                            add_cve(comp, cve, version, score, vector, source, osv_fixed_version(vuln, qname, comp['version']))
                    except Exception as exc:
                        unresolved(comp, '%s lookup failed (%s)' % (vid, str(exc)[:80]))
            # 沒有 v3 分數的 CVE 用 NVD 補分數; GitHub 評等高的先查, 次數用完時最可能 >= 7 的已查過 (查不到 -> NOT_EVALUATED)
            rank = {'CRITICAL': 0, 'HIGH': 1, 'MODERATE': 2, 'LOW': 3}
            for comp, qname, vuln, cve, severity in sorted(pending, key=lambda p: rank.get(p[4], 1)):
                try:
                    nvd = nvd_score(cve)
                except Exception as exc:
                    unresolved(comp, '%s lookup failed (%s)' % (cve, str(exc)[:80]))
                    continue
                if not nvd:
                    unresolved(comp, cve + ' has no CVSS v3 score')
                    continue
                add_cve(comp, cve, nvd[0], nvd[1], nvd[2], 'NVD', osv_fixed_version(vuln, qname, comp['version']))

        for comp in maven:
            if comp['version'] or not comp.get('possible'):
                continue
            items = sorted(comp['possible'], key=lambda p: -(p['score'] if isinstance(p['score'], float) else LIB_CVSS_THRESHOLD))
            if comp['status'] == 'ok':
                comp['status'] = 'version_unknown'
            review.append('%s: version unknown; high-severity CVEs in versions: %s%s; needs manual review' % (
                lib_short_name(comp['name']), '; '.join('%s (%s) %s' % (p['cve'], p['score'], ', '.join(p['ranges'][:2]))
                                                         for p in items[:3]),
                '; and %d more CVE%s' % (len(items) - 3, 's' if len(items) > 4 else '') if len(items) > 3 else ''))

        # 原生函式庫: NVD 依 CPE 名稱與版本查 (NVD 自己比對受影響版本)
        for comp in [c for c in components if c['ecosystem'] == 'native' and c['name'] != 'libwebp (symbols)']:
            cpe = next(p for n, _, p, _ in LIB_NATIVE_BANNERS if n == comp['name'])
            cpe = 'cpe:2.3:a:%s:%s:*:*:*:*:*:*:*' % (cpe, comp['version'])
            try:
                data = nvd_get('https://services.nvd.nist.gov/rest/json/cves/2.0?' + urllib.parse.urlencode(
                    {'cpeName': cpe, 'isVulnerable': '', 'resultsPerPage': 2000}))
                rows = data.get('vulnerabilities')
                if not isinstance(rows, list) or data.get('totalResults', 0) > len(rows):
                    raise ValueError('NVD result incomplete')
                for row in rows:
                    record = row.get('cve', {}) if isinstance(row, dict) else {}
                    cve = record.get('id', '')
                    if not re.fullmatch(r'CVE-\d{4}-\d{4,}', cve) or record.get('vulnStatus', '').lower() == 'rejected':
                        continue
                    score = nvd_cvss3(record)
                    if score:
                        add_cve(comp, cve, score[0], score[1], score[2], 'NVD ' + cpe)
                    else:
                        unresolved(comp, cve + ' has no CVSS v3 score')
            except Exception as exc:
                unresolved(comp, 'NVD lookup failed (%s)' % str(exc)[:80])

        # 會判 Failed 的 CVE: 分數最高的前 LIB_MAX_NVD_CONFIRM 個改用 NVD 分數 (低於門檻就移除); 查不到或次數用完保留 OSV 分數
        top = {}
        for f in findings:
            if not f['source'].startswith('NVD'):
                top[f['cve']] = max(top.get(f['cve'], 0), f['score'])
        for cve in sorted(top, key=lambda c: -top[c])[:LIB_MAX_NVD_CONFIRM]:
            try:
                nvd = nvd_score(cve)
            except Exception:
                continue
            for f in findings:
                if nvd and f['cve'] == cve:
                    f.update(cvss_version=nvd[0], score=nvd[1], vector=nvd[2], source='NVD')
        findings = [f for f in findings if f['score'] >= LIB_CVSS_THRESHOLD]
        # 建議版本: 同一函式庫所有 Failed CVE 的修補版本取最大, 照著更新就全部修掉;
        # 有 CVE 查不到修補版本、建議版本本身在 OSV 還有漏洞、或查詢失敗 -> 留空 (報告改建議更新到最新版)
        targets = {}
        for f in findings:
            key, cur = (f['library'], f['version']), targets.get((f['library'], f['version']))
            if cur == '' or not f.get('fixed'):
                targets[key] = ''
            elif cur is None or lib_version_key(f['fixed']) > lib_version_key(cur):
                targets[key] = f['fixed']
        ecosystems = {(f['library'], f['version']): f.get('ecosystem') for f in findings}
        check = [(k, v) for k, v in targets.items() if v and ecosystems.get(k) in LIB_OSV_ECOSYSTEMS]
        if check:
            try:
                rows = http('https://api.osv.dev/v1/querybatch', {'queries': [
                    {'package': {'ecosystem': ecosystems[k], 'name': k[0]}, 'version': v} for k, v in check]}, timeout()).get('results')
                if not isinstance(rows, list) or len(rows) != len(check):
                    raise ValueError('invalid OSV batch response')
                for (k, v), row in zip(check, rows):
                    if (row or {}).get('vulns'):
                        targets[k] = ''
            except Exception:
                for k, v in check:
                    targets[k] = ''
        for f in findings:
            f['fix_all'] = targets.get((f['library'], f['version']), '')

        for comp in components:
            if comp['status'] == 'vulnerable' and not any(f['library'] == comp['name'] and f['version'] == comp['version']
                                                          for f in findings):
                comp['status'] = 'ok'

        # 原生函式庫 (沒有版本字串): 認得出的查 NVD 這個產品的高風險 CVE (critical 優先); 有就 NOT_EVALUATED 並列出一個
        def nvd_product_by_name(stem):
            key = 'name:' + stem
            if key not in disk:
                base = stem[3:] if stem.startswith('lib') else stem
                data = nvd_get('https://services.nvd.nist.gov/rest/json/cpes/2.0?' + urllib.parse.urlencode(
                    {'keywordSearch': base, 'resultsPerPage': 100}))
                cpe = ''
                for row in data.get('products', []):
                    parts = (row.get('cpe') or {}).get('cpeName', '').split(':')
                    if len(parts) > 4 and parts[2] == 'a' and parts[4] in (stem, base):
                        cpe = parts[3] + ':' + parts[4]
                        break
                disk[key] = {'time': time.time(), 'score': cpe}
            return disk[key]['score'] or None
        def nvd_product_high_cve(cpe):
            key = 'product:' + cpe
            if key not in disk:
                example = None
                for level in ('CRITICAL', 'HIGH'):
                    data = nvd_get('https://services.nvd.nist.gov/rest/json/cves/2.0?' + urllib.parse.urlencode(
                        {'virtualMatchString': 'cpe:2.3:a:' + cpe, 'cvssV3Severity': level, 'resultsPerPage': 20}))
                    for row in data.get('vulnerabilities', []):
                        record = row.get('cve', {})
                        score = nvd_cvss3(record)
                        if score and score[1] >= LIB_CVSS_THRESHOLD and (not example or score[1] > example[1]):
                            example = (record.get('id', ''), score[1])
                    if example:
                        break
                disk[key] = {'time': time.time(), 'score': list(example) if example else None}
            return disk[key]['score']
        known_native = {c['name'] for c in components if c['ecosystem'] == 'native'}
        name_lookups = 0
        for name, (cpe, paths) in sorted(native_products(apk, unidentified, known_native).items()):
            try:
                if cpe is None:
                    if name_lookups >= LIB_MAX_NVD_NAME_LOOKUPS:
                        continue
                    name_lookups += 1
                    name = name[1:]
                    cpe = nvd_product_by_name(name)
                    if not cpe:
                        continue  # 對不到 NVD 產品 (多半是 App 自己的 .so)
                example = nvd_product_high_cve(cpe)
            except Exception as exc:
                review.append('%s (%s): NVD lookup failed (%s); needs manual review' % (name, paths[0], str(exc)[:60]))
                continue
            if example:
                review.append('%s (%s): version unknown; high-severity CVEs in some versions, e.g. %s (%s); '
                              'needs manual review' % (name, paths[0].rsplit('/', 1)[-1], example[0], example[1]))

        lib_nvd_cache_save(disk)
        if findings:
            verdict = 'WARNING'
        elif review or not components:
            verdict = 'NOT_EVALUATED'
            if not components:
                review.append('no library name and version found in the APK')
        else:
            verdict = 'PASS'
        findings.sort(key=lambda f: -f['score'])
        return {'verdict': verdict, 'has_finding': bool(findings), 'findings': findings, 'review': review,
                'components': components, 'unidentified': unidentified, 'maven_unresolved': maven_unresolved,
                'threshold': LIB_CVSS_THRESHOLD}

    app.run(host='0.0.0.0', port=port)
if __name__ == "__main__":
    os.makedirs("./uploads", exist_ok=True)
    apk_env = os.environ.get('APK_PATH', None)
    run_androguard_server(8010, apk_env)
