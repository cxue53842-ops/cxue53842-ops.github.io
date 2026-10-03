import os
import sys
import psutil
import platform
import subprocess
import requests
import time
import webbrowser
import threading
import tempfile
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify, send_from_directory
from duckduckgo_search import DDGS

app = Flask(__name__)

# --- 全域防火牆攔截狀態機 ---
fw_event = threading.Event()
fw_decision = False
current_intercepted_target = ""

def request_user_permission(target_info):
    """攔截未授權的外部網路請求，暫停執行並等待本人手動核准"""
    global current_intercepted_target, fw_decision
    current_intercepted_target = target_info
    fw_event.clear()  # 鎖定網絡通道
    print(f"[FIREWALL] 偵測到流出請求: {target_info}。等待主機所有人審查...")
    
    # 阻塞當前執行緒，直到前端調用 /api/firewall/reply 釋放鎖定
    is_signed = fw_event.wait(timeout=60)
    if not is_signed:
        print("[FIREWALL TIMEOUT] 審查超時。安全起見，已自動拒絕流出。")
        return False
    return fw_decision

# --- 核心硬體檢測與大模型自動配給矩陣 ---
def detect_hardware_and_recommend():
    recommendation = {
        "cpu": platform.processor() or "Generic Processor",
        "ram_gb": round(psutil.virtual_memory().total / (1024**3), 2),
        "gpu": "未檢測到獨立 GPU (使用 CPU 解碼)",
        "model": "dolphin-mistral:latest",
        "reason": "配給 7B 級別輕量無審查模型以優化速度。"
    }
    try:
        if sys.platform == "win32":
            gpu_info = subprocess.check_output("wmic path win32_VideoController get name", shell=True).decode()
            if "NVIDIA" in gpu_info:
                recommendation["gpu"] = [line.strip() for line in gpu_info.split('\n') if line.strip() and "Name" not in line]
        else:
            gpu_info = subprocess.check_output("lspci | grep -i nvidia", shell=True).decode()
            if gpu_info: 
                recommendation["gpu"] = "NVIDIA CUDA Architecture"
    except: 
        pass

    if recommendation["ram_gb"] >= 32 or "NVIDIA" in str(recommendation["gpu"]):
        recommendation["model"] = "llama3-lexi-uncensored:latest"
        recommendation["reason"] = "主機性能強勁，已自動鎖定 8B 級別高脈絡深層無審查模型。"
    elif recommendation["ram_gb"] < 8:
        recommendation["model"] = "qwen2.5:1.5b"
        recommendation["reason"] = "記憶體低於安全臨界值，配給超輕量模型防範崩潰。"
    return recommendation

def auto_setup_and_launch():
    """背景調度器：自動下載大模型並開啟網頁終端"""
    time.sleep(1.5)
    hardware = detect_hardware_and_recommend()
    target_model = hardware["model"]
    try:
        tags_response = requests.get("http://localhost:11434/api/tags", timeout=5)
        local_models = [m["name"] for m in tags_response.json().get("models", [])]
        if target_model not in local_models and f"{target_model}:latest" not in local_models:
            print(f"[SYSTEM] 正在自動拉取無審查模型節點: {target_model} ...")
            requests.post("http://localhost:11434/api/pull", json={"name": target_model}, timeout=1800)
    except: 
        pass
    webbrowser.open("http://127.0.0.1:5000")

# --- 隔離代碼沙盒執行內核 ---
def run_code_in_sandbox(code, timeout=10):
    if any(k in code for k in ["requests", "urllib", "socket", "http", "ftp", "curl", "wget"]):
        if not request_user_permission("Sandbox Script Execution (腳本試圖建立外部通訊鏈結)"):
            return "[FIREWALL BLOCKED] 本尊已安全重置防火牆閘門，阻止本腳本的公網流出權限。"

    with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode='w', encoding='utf-8') as temp_file:
        temp_file.write(code)
        temp_file_path = temp_file.name
    try:
        process = subprocess.run(
            [sys.executable, temp_file_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout,
            env={"PYTHONIOENCODING": "utf-8"}
        )
        output = "--- [SANDBOX OUTPUT STREAM] ---\n"
        if process.stdout: output += process.stdout
        if process.stderr: output += f"\n[STDERR ALERT]:\n{process.stderr}"
        return output if (process.stdout or process.stderr) else "[SYSTEM] 腳本執行完畢，內部無文字輸出流。"
    except subprocess.TimeoutExpired:
        return f"[SANDBOX TIMEOUT] 腳本執行已超過安全上限 {timeout} 秒，防火牆強制熔斷。"
    finally:
        if os.path.exists(temp_file_path): os.remove(temp_file_path)

# --- 網路搜索與暗網雷達攔截器 ---
def search_onion_network(query, tor_proxy=None):
    if not request_user_permission(f"Dark Web Proxy Probe (暗網檢索: '{query}')"):
        return "[FIREWALL BLOCKED] 用戶封鎖了 Tor 匿名出口隧道的配置。"
    try:
        res = requests.get("https://ahmia.fi", params={'q': query}, proxies={"http": tor_proxy, "https": tor_proxy} if tor_proxy else None, timeout=20)
        soup = BeautifulSoup(res.text, 'html.parser')
        onion_results = []
        for item in soup.find_all('li', class_='result')[:5]:
            title_a = item.find('a')
            if title_a and ".onion" in title_a['href']:
                onion_results.append(f"🏴‍☠️ {title_a.text.strip()}\n網址: {title_a['href']}\n---")
        return "\n".join(onion_results) if onion_results else "[INFO] 未搜尋到相關在線 .onion 節點。"
    except Exception as e: return f"[ERROR] 無法連線至暗網網關: {str(e)}"

def execute_web_search(query, tor_proxy=None):
    if not request_user_permission(f"Surface Network Crawl (公網搜索: '{query}')"):
        return "[FIREWALL BLOCKED] 用戶已撤銷表網公網出口權限。"
    try:
        with DDGS(proxies={"http": tor_proxy, "https": tor_proxy} if tor_proxy else None, timeout=15) as ddgs:
            return "\n".join([f"標題: {r['title']}\n摘要: {r['body']}\n---" for r in ddgs.text(query, max_results=4)])
    except Exception as e: return f"[ERROR] 檢索失敗: {str(e)}"

# --- Flask 後端伺服器架構 ---
@app.route('/')
def index(): 
    return send_from_directory('.', 'index.html')

@app.route('/api/hardware', methods=['GET'])
def get_hardware(): 
    return jsonify(detect_hardware_and_recommend())

@app.route('/api/firewall/check', methods=['GET'])
def fw_check():
    if not fw_event.is_set() and current_intercepted_target != "":
        return jsonify({"intercepted": True, "target": current_intercepted_target})
    return jsonify({"intercepted": False})

@app.route('/api/firewall/reply', methods=['POST'])
def fw_reply():
    global fw_decision
    data = request.json
    fw_decision = data.get("allow", False)
    fw_event.set() # 釋放執行緒阻塞鎖
    return jsonify({"status": "acknowledged"})

@app.route('/api/sandbox', methods=['POST'])
def api_sandbox():
    return jsonify({"result": run_code_in_sandbox(request.json.get("code", ""), int(request.json.get("timeout", 10)))})

@app.route('/api/search_onion', methods=['POST'])
def api_search_onion():
    return jsonify({"result": search_onion_network(request.json.get("query"), request.json.get("proxy"))})

@app.route('/api/search', methods=['POST'])
def api_search():
    return jsonify({"result": execute_web_search(request.json.get("query"), request.json.get("proxy"))})

@app.route('/api/generate', methods=['POST'])
def generate():
    data = request.json
    if data.get("auto_search") and any(k in data["prompt"].lower() for k in ["onion", "暗網", "最新", "今天", "搜尋", "新聞"]):
        if request_user_permission("AI Automated Real-time Intelligence Search"):
            search_context = execute_web_search(data["prompt"], data.get("proxy"))
            data["system"] += f"\n\n[REAL-TIME DATA CONTEXT]\n{search_context}"
        else:
            data["system"] += "\n\n[SYSTEM WARNING] 公網連線被用戶防火牆實時切斷。請僅能依靠內部離線知識庫作答。"
    try:
        response = requests.post("http://localhost:11434/api/generate", json=data, timeout=300)
        return jsonify(response.json())
    except: return jsonify({"error": "Ollama Core Offline"}), 500

if __name__ == '__main__':
    print("=" * 60)
    print(" [THE MYTHOS ENGINE v5.1] 本地後端驅動就緒 ")
    print("=" * 60)
    threading.Thread(target=auto_setup_and_launch, daemon=True).start()
    app.run(host='127.0.0.1', port=5000, debug=False)
