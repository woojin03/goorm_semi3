import os
import json
import socket
import logging
import ipaddress
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from dotenv import load_dotenv
import requests
from pymongo import MongoClient
import time

# === 설정 로드 ===
load_dotenv()
NVD_API_KEY = os.getenv("NVD_API_KEY") 

with open("config.json") as f:
    config = json.load(f)

scan_mode = config.get("scan_mode", "fast")

# 포트 목록 설정
if scan_mode == "full":
    ports_to_check = list(range(1, 65536))
else:
    default_ports = [21, 22, 23, 80, 443, 3306, 3389, 8080, 8443, 12345]

    ports = config.get("ports", [])
    port_range = config.get("port_range", [])

    if ports:
        ports_to_check = ports
    elif isinstance(port_range, list) and len(port_range) == 2:
        start, end = port_range
        if isinstance(start, int) and isinstance(end, int) and 1 <= start <= 65535 and 1 <= end <= 65535:
            ports_to_check = list(range(start, end + 1))
        else:
            ports_to_check = default_ports
    else:
        ports_to_check = default_ports


USE_SHODAN = scan_mode != "full"



# === 서비스명 정규화 ===
SERVICE_NAME_MAP = {
    "apache httpd": "apache",
    "httpd": "apache",
    "mariadb": "mysql",
    "nginx web server": "nginx",
    "ms-sql-s": "microsoft sql server",
    "postgresql": "postgres"
}

# === 로깅 설정 ===
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("scanner")

# === 위험도 계산 ===
def calculate_risk(port, cves, is_shadow):
    score = 0
    if port in [21, 23, 12345, 31337]:
        score += 5
    if cves:
        score += len(cves) * 2
        for cve in cves:
            if cve.get("cvss", 0) >= 7.0:
                score += 3
    if is_shadow:
        score += 15

    return "high" if score >= 15 else "medium" if score >= 7 else "low"

def load_registered_assets():
    mongo_uri = os.getenv("MONGO_URI")
    client = MongoClient(mongo_uri)
    db = client.get_default_database()
    collection = db["registered_assets"]

    assets = collection.find({}, {"ip": 1, "ports.port": 1, "_id": 0})
    registered = set()

    for asset in assets:
        ip = asset.get("ip")
        for port_info in asset.get("ports", []):
            port = port_info.get("port")
            if ip and port:
                registered.add((ip, int(port)))

    return registered

REGISTERED_ASSETS = load_registered_assets()

def save_report_to_mongodb(results):
    mongo_uri = os.getenv("MONGO_URI")
    client = MongoClient(mongo_uri)
    db = client.get_default_database()
    collection = db["reports"]

    korea_time = datetime.utcnow() + timedelta(hours=9)

    report_doc = {
        "scan_date": korea_time.isoformat() + "Z",  # ✅ 한국 시간으로 저장
        "assets": results
    }

    collection.insert_one(report_doc)
    logger.info("✅ 스캔 결과가 MongoDB 'reports' 컬렉션에 저장되었습니다.")

# === CVE 상세 설명 조회 (상위 3개 CVSS만 유지)
def fetch_cve_descriptions(cve_list):
    detailed = []
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

    for idx, cve_id in enumerate(cve_list, 1):
        logger.info(f"    ▶ ({idx}/{len(cve_list)}) {cve_id} 질의 중...")
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            r = requests.get(url, headers=headers)
            if r.status_code == 403:
                logger.warning("    ⚠️ 403 Forbidden - 요청이 너무 많을 수 있음. 대기 후 재시도")
                time.sleep(3)
                r = requests.get(url, headers=headers)
            r.raise_for_status()
            data = r.json()

            cve_data = data.get("vulnerabilities", [])[0].get("cve", {})
            descriptions = cve_data.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

            metrics = cve_data.get("metrics", {})
            cvss_score = 0
            for cvss_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if cvss_key in metrics:
                    cvss_data = metrics[cvss_key][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0)
                    break

            detailed.append({
                "id": cve_id,
                "description": desc,
                "cvss": cvss_score
            })

            # ✅ 전체 설명 로그 출력
            logger.info(f"    ✔️ {cve_id} → CVSS: {cvss_score}")
            logger.info(f"       설명: {desc}")

        except Exception as e:
            logger.error(f"    ❌ NVD API 호출 실패 {cve_id}: {e}")
            detailed.append({"id": cve_id, "description": "", "cvss": 0})

        time.sleep(1.2)  # Rate limit 회피를 위한 대기

    detailed.sort(key=lambda x: x.get("cvss", 0), reverse=True)
    return detailed[:3]

# === Nmap 실행 ===

def query_nvd_cpe(product, version):
    keyword = f"{product} {version}"
    url = f"https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch={keyword}"
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        cpes = [
            item["cpe"]["cpeName"]
            for item in data.get("products", [])
            if "cpe" in item
        ]
        cve_ids = set()
        for cpe in cpes:
            cve_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe}"
            cve_response = requests.get(cve_url, headers=headers)
            if cve_response.status_code == 403:
                time.sleep(3)
                cve_response = requests.get(cve_url, headers=headers)
            cve_response.raise_for_status()
            cve_data = cve_response.json()
            cve_ids.update(item['cve']['id'] for item in cve_data.get('vulnerabilities', []))
            time.sleep(1.2)
        return list(cve_ids), 0
    except Exception as e:
        logger.error(f"❌ NVD CPE 쿼리 실패 ({product} {version}): {e}")
        return [], 0
def run_nmap(ip):
    start_time = time.time()
    cmd = ["nmap", "-Pn", "-sS", "-sV", "-p", ",".join(map(str, ports_to_check)), "-oX", "-", ip]
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
        duration = time.time() - start_time
        logger.info(f"[예상 시간] {ip} 스캔 소요: {duration:.2f}초")
        return parse_nmap(ip, output), duration
    except Exception as e:
        logger.error(f"nmap scan failed for {ip}: {e}")
        return None, 0

# === Nmap XML 파싱 ===
def parse_nmap(ip, xml_data):
    try:
        root = ET.fromstring(xml_data)
        host = root.find("host")
        if host is None:
            logger.warning(f"No <host> tag found in Nmap output for {ip}")
            return None

        ports_info = []
        hostname = host.find("hostnames/hostname")
        host_name = hostname.get("name") if hostname is not None else None

        port_elements = host.findall("ports/port")
        total_ports = len(port_elements)

        for idx, port in enumerate(port_elements, 1):
            state = port.find("state").get("state")
            if state != "open":
                continue

            port_num = int(port.get("portid"))
            service_elem = port.find("service")
            service = service_elem.get("name")
            version = service_elem.get("version") or "unknown"
            product = service_elem.get("product") or service
            product = SERVICE_NAME_MAP.get(product.lower(), product.lower())

            cve_ids, shodan_count = query_nvd_cpe(product, version)
            max_cves = config.get("max_cves_per_port", 10)
            cve_ids = cve_ids[:max_cves]
            logger.info(f"[{ip}] NVD로 {len(cve_ids)}개 CVE 질의 중...")

            cve_details = fetch_cve_descriptions(cve_ids)
            ports_info.append({
                "port": port_num,
                "service": product,
                "version": version,
                "cves": cve_details,
            })

        total_cves = sum(len(p["cves"]) for p in ports_info)
        logger.info(f"[{ip}] 발견된 취약점 수: {total_cves}")

        is_shadow = False
        for port_info in ports_info:
            if (ip, port_info['port']) not in REGISTERED_ASSETS:
                is_shadow = True
                break
        first = ports_info[0] if ports_info else {}
        risk = calculate_risk(
            first.get("port", 0),
            first.get("cves", []),
            is_shadow,
        )

        return {
            "ip": ip,
            "hostname": host_name,
            "open_ports": ports_info,
            "risk_level": risk,
            "is_shadow_it": is_shadow,
                "product": first.get("service"),
                "version": first.get("version"),
                "vulns": [c["id"] for c in first.get("cves", [])],
        }
        
    except ET.ParseError:
        logger.error(f"XML parse error from Nmap for {ip}")
        return None

# === 실행 ===
if __name__ == "__main__":
    logger.info("=== Nmap 스캐너 시작 (모드: %s) ===" % scan_mode)
    targets = []
    for entry in config.get("ip", []):
        try:
            net = ipaddress.ip_network(entry, strict=False)
            targets.extend([str(ip) for ip in net.hosts()])
        except ValueError:
            targets.append(entry)
    results = []
    failed_ips = []
    total_targets = len(targets)
    completed = 0

    for ip in targets:
        logger.info(f"Scanning IP: {ip} (검사 포트 개수: {len(ports_to_check)})")
        result, duration = run_nmap(ip)
        completed += 1

        if completed % 10 == 0 or completed == total_targets:
            logger.info(f"[진행률] {completed}/{total_targets} IP 완료")

        if result:
            results.append(result)
        else:
            failed_ips.append(ip)

    logger.info("=== Nmap 스캐너 종료 ===")
    logger.info(f"총 대상: {total_targets} | 성공: {len(results)} | 실패: {len(failed_ips)}")
    if failed_ips:
        logger.info(f"스캔 실패한 IP 목록: {', '.join(failed_ips)}")

    # ✅ 결과 저장 함수 호출
    save_report_to_mongodb(results)

