from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn
from datetime import datetime
import pytz
from db import db
from fastapi.middleware.cors import CORSMiddleware
from bson import ObjectId
from fastapi import Query
from dateutil import parser
from collections import defaultdict
from bson import Regex
from typing import Optional
import csv
from io import StringIO
from fastapi.responses import StreamingResponse, JSONResponse
import subprocess


app = FastAPI()


# CORS 허용 설정 (프론트와 통신 시 필요)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 배포 시에는 도메인 제한 권장
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# 정적 파일 경로 등록
app.mount("/static", StaticFiles(directory="static"), name="static")
# 템플릿 경로 등록
templates = Jinja2Templates(directory="templates")

# 현재 한국 시간 반환 함수
def get_korea_time():
    return datetime.now(pytz.timezone('Asia/Seoul')).strftime("%Y-%m-%d %H:%M")


# db 연동 -> ObjectId를 문자열로 변환
def serialize_document(doc):
    doc["_id"] = str(doc["_id"])
    return doc


def serialize_report(doc):
    doc = serialize_document(doc)
    if isinstance(doc.get("scan_date"), datetime):
        doc["scan_date"] = doc["scan_date"].strftime("%Y-%m-%d")

    for asset in doc.get("assets", []):
        asset["risk_count"] = sum(len(p.get("cves", [])) for p in asset.get("open_ports", []))
    return doc


@app.get("/reports")
async def get_reports():
    raw_reports = await db.reports.find().to_list(100)
    return [serialize_document(report) for report in raw_reports]

@app.get("/assets")
async def get_assets():
    raw_assets = await db.registered_assets.find().to_list(100)
    return [serialize_document(asset) for asset in raw_assets]

# 최신 보고서 1건 API (/latest-report)
@app.get("/latest-report")
async def latest_report():
    latest = await db.reports.find().sort("scan_date", -1).limit(1).to_list(1)
    if latest:
        return serialize_report(latest[0])
    return {"message": "No report found"}



# overview.html ----------------------------------------------------------------
# overview.html의 요약보기에 대한 정보
@app.get("/overview-assets")
async def overview_assets():
    reports = await db.reports.find().sort("scan_date", -1).to_list(100)
    if not reports:
        return []

    date_dict = {}

    for report in reports:
        scan_date_raw = report.get("scan_date")
        
        # datetime 타입이면 string으로 변환
        if isinstance(scan_date_raw, datetime):
            scan_date_str = scan_date_raw.strftime("%Y-%m-%d")
        else:
            scan_date_str = parser.isoparse(scan_date_raw).strftime("%Y-%m-%d")

        for asset in report.get("assets", []):
            open_ports = asset.get("open_ports", [])
            port_count = len(open_ports)
            vuln_count = sum(len(p.get("cves", [])) for p in open_ports)
            risk_count = vuln_count

            asset_summary = {
                "ip": asset.get("ip"),
                "scan_date": scan_date_raw,
                "port_count": port_count,
                "vuln_count": vuln_count,
                "risk_count": risk_count,
                "risk_level": asset.get("risk_level", "미정"),  # ✅ 추가
                "is_shadow_it": asset.get("is_shadow_it", False)
            }

            date_dict.setdefault(scan_date_str, []).append(asset_summary)

    # 날짜 기준 내림차순 정렬
    grouped_data = [{"date": date, "assets": date_dict[date]} for date in sorted(date_dict.keys(), reverse=True)]
    return grouped_data


# overview 상세보기 창
@app.get("/asset-detail")
async def asset_detail(ip: str = Query(...), scan_date: str = Query(...)):
    parsed = parser.isoparse(scan_date)
    scan_date_only = parsed.strftime("%Y-%m-%d")

    report = await db.reports.find_one({"scan_date": Regex(f"^{scan_date_only}")})

    if not report:
        return {"error": "해당 날짜의 리포트가 존재하지 않습니다."}

    for asset in report.get("assets", []):
        if asset.get("ip") == ip:
            # CVE ID 마다 mitigation 가져오기
            for port in asset.get("open_ports", []):
                for cve in port.get("cves", []):
                    cve_doc = await db.cve_list.find_one({"cve_id": cve["id"]})
                    if cve_doc:
                        cve["description"] = cve_doc.get("description", "설명 없음")
                        cve["mitigation"] = cve_doc.get("mitigation", "대응방안 없음")

            return {
            "scan_date": report.get("scan_date"),
            "ip": ip,
            "hostname": asset.get("hostname", ""),
            "open_ports": asset.get("open_ports", []),
            "is_shadow_it": asset.get("is_shadow_it", False),
            "risk_level": asset.get("risk_level", "미정")
        }

    return {"error": f"{ip} 에 해당하는 자산을 찾을 수 없습니다."}




# shadow IT------------------------------------------------------------------
# shadow IT만 필터링한 API (/shadow-assets)
@app.get("/shadow-assets")
async def shadow_assets():
    # 모든 보고서를 가져옴 (최신순 정렬)
    reports = await db.reports.find().sort("scan_date", -1).to_list(100)

    if not reports:
        return []

    # 등록된 자산 IP 가져오기
    registered_assets = await db.registered_assets.find().to_list(1000)
    registered_ips = {asset.get("ip") for asset in registered_assets}

    result = []
    for report in reports:
        scan_date = report.get("scan_date")
        if isinstance(scan_date, datetime):
            scan_date = scan_date.strftime("%Y-%m-%d")

        for asset in report.get("assets", []):
            asset["scan_date"] = scan_date
            asset["is_registered"] = asset.get("ip") in registered_ips

            # 위험도 개수 계산
            if "risk_count" not in asset:
                asset["risk_count"] = sum(len(p.get("cves", [])) for p in asset.get("open_ports", []))

            result.append(asset)

    return result



# insight 그래프---------------------------------------------------------------------
#  평균 위험도 추이 API (예: /risk-trend)
@app.get("/risk-trend")
async def risk_trend():
    reports = await db.reports.find().sort("scan_date", -1).to_list(10)

    grouped = {}
    for report in reports:
        date = report["scan_date"].strftime("%Y-%m-%d") if isinstance(report["scan_date"], datetime) else report["scan_date"][:10]
        if date not in grouped:
            grouped[date] = report

    selected_dates = sorted(grouped.keys(), reverse=True)[:3]
    selected_reports = [grouped[date] for date in selected_dates]

    scores = { "low": 1, "medium": 2, "high": 3 }
    trend = []

    for r in selected_reports[::-1]:
        date = r["scan_date"].strftime("%Y-%m-%d") if isinstance(r["scan_date"], datetime) else r["scan_date"][:10]
        level_sum, count = 0, 0
        for a in r["assets"]:
            level = a.get("risk_level")
            if level in scores:
                level_sum += scores[level]
                count += 1
        avg = round(level_sum / count, 2) if count else 0
        trend.append({"date": date, "avg_risk": avg})

    return trend

# shadow it 장비 추이
@app.get("/shadow-trend")
async def shadow_trend():
    reports = await db.reports.find().sort("scan_date", -1).to_list(10)

    registered_assets = await db.registered_assets.find().to_list(1000)
    registered_ips = {asset.get("ip") for asset in registered_assets}

    grouped = {}
    for report in reports:
        date = report["scan_date"].strftime("%Y-%m-%d") if isinstance(report["scan_date"], datetime) else report["scan_date"][:10]
        if date not in grouped:
            grouped[date] = report

    selected_dates = sorted(grouped.keys(), reverse=True)[:3]
    selected_reports = [grouped[date] for date in selected_dates]

    trend = []
    for r in selected_reports[::-1]:
        date = r["scan_date"].strftime("%Y-%m-%d") if isinstance(r["scan_date"], datetime) else r["scan_date"][:10]
        shadow_count = sum(1 for asset in r["assets"] if asset.get("ip") not in registered_ips)
        trend.append({"date": date, "shadow_count": shadow_count})

    return trend


# 열린 포트 개수
@app.get("/port-count")
async def port_stats():
    # 최신 보고서 1개 가져오기
    latest = await db.reports.find().sort("scan_date", -1).limit(1).to_list(1)
    if not latest:
        return []

    report = latest[0]
    assets = report.get("assets", [])

    port_info = []
    for asset in assets:
        ip = asset.get("ip", "unknown")
        port_count = len(asset.get("open_ports", []))
        port_info.append({
            "ip": ip,
            "port_count": port_count
        })

    # 포트 개수 기준 내림차순 정렬 후 상위 5개만
    sorted_top = sorted(port_info, key=lambda x: x["port_count"], reverse=True)[:5]
    return sorted_top


# 취약점 서비스
@app.get("/vuln-services")
async def vuln_services():
    # 최신 보고서 1개 가져오기
    latest = await db.reports.find().sort("scan_date", -1).limit(1).to_list(1)
    if not latest:
        return []

    report = latest[0]
    assets = report.get("assets", [])

    service_counter = {}

    for asset in assets:
        for port in asset.get("open_ports", []):
            service = port.get("service", "unknown")
            cve_count = len(port.get("cves", []))
            if cve_count > 0:
                if service in service_counter:
                    service_counter[service] += 1
                else:
                    service_counter[service] = 1

    # 결과 정렬 및 변환
    sorted_services = sorted(service_counter.items(), key=lambda x: x[1], reverse=True)
    result = [{"service": s, "count": c} for s, c in sorted_services]

    return result

# 취약점 자산 텍스트
@app.get("/top-risk-assets")
async def top_risk_assets():
    latest = await db.reports.find().sort("scan_date", -1).limit(1).to_list(1)
    if not latest:
        return []

    report = latest[0]
    assets = report.get("assets", [])

    level_score = { "high": 3, "medium": 2, "low": 1, "미정": 0 }

    scored = []

    for asset in assets:
        risk_level = asset.get("risk_level", "미정")
        risk_count = sum(len(p.get("cves", [])) for p in asset.get("open_ports", []))
        description = ""

        # CVE ID -> cve_list에서 description 찾기
        for port in asset.get("open_ports", []):
            if port.get("cves"):
                cve_id = port["cves"][0]["id"]
                cve_doc = await db.cve_list.find_one({"cve_id": cve_id})
                if cve_doc:
                    description = cve_doc.get("description", "")
                break

        scored.append({
            "ip": asset.get("ip"),
            "risk_level": risk_level,
            "risk_count": risk_count,
            "description": description[:100] if description else "설명 없음"
        })

    sorted_assets = sorted(
        scored,
        key=lambda a: (level_score.get(a["risk_level"], 0), a["risk_count"]),
        reverse=True
    )

    return sorted_assets[:3]



# csvtools--------------------------------------------------------------------------
# ✅ 날짜 범위 내 데이터를 미리보기용 JSON으로 반환
@app.get("/preview-csv")
async def preview_csv(start_date: str = Query(...), end_date: str = Query(...)):
    try:
        start = datetime.fromisoformat(start_date)
        end = datetime.fromisoformat(end_date)
    except ValueError:
        return JSONResponse(status_code=400, content={"error": "날짜 형식이 잘못되었습니다."})

    reports = await db.reports.find({
        "scan_date": {
            "$gte": start_date,
            "$lte": end_date + "T23:59:59"
        }
    }).to_list(100)

    # 결과 축약 후 반환
    result = []
    for r in reports:
        r["_id"] = str(r["_id"])
        result.append(r)

    return result


# ✅ 날짜 범위 내 데이터를 CSV로 다운로드
@app.get("/download-csv")
async def download_csv(start_date: str = Query(...), end_date: str = Query(...)):
    try:
        start = datetime.fromisoformat(start_date)
        end = datetime.fromisoformat(end_date)
    except ValueError:
        return JSONResponse(status_code=400, content={"error": "날짜 형식이 잘못되었습니다."})

    reports = await db.reports.find({
        "scan_date": {
            "$gte": start_date,
            "$lte": end_date + "T23:59:59"
        }
    }).to_list(100)

    if not reports:
        return JSONResponse(status_code=404, content={"error": "해당 날짜 범위의 데이터가 없습니다."})

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["Scan Date", "IP", "Hostname", "Port", "Service", "Risk Level", "CVE 수"])

    for report in reports:
        scan_date = report.get("scan_date", "")
        for asset in report.get("assets", []):
            ip = asset.get("ip", "")
            hostname = asset.get("hostname", "")
            risk_level = asset.get("risk_level", "미정")
            for port in asset.get("open_ports", []):
                service = port.get("service", "")
                cve_count = len(port.get("cves", []))
                port_num = port.get("port", "")
                writer.writerow([scan_date, ip, hostname, port_num, service, risk_level, cve_count])

    output.seek(0)
    filename = f"export_{start_date}_to_{end_date}.csv"
    return StreamingResponse(output, media_type="text/csv", headers={
        "Content-Disposition": f"attachment; filename={filename}"
    })


# port scan--------------------------------------------------------------------------
# scan docker cmd 실행?
@app.get("/scan-port")
async def scan_port():
    def run():
        cmd = ["docker-compose", "run", "--rm", "scanner", "python3", "scanner_test2.py"]
        process = subprocess.Popen(cmd, cwd="Scanner", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        for line in iter(process.stdout.readline, ''):
            yield line

        process.stdout.close()
        process.wait()

    return StreamingResponse(run(), media_type="text/plain")


#----------------------------------------------------------------------------------
# 루트 및 overview 페이지
@app.get("/", response_class=HTMLResponse)
def read_root(request: Request):
    return templates.TemplateResponse("overview.html", {
        "request": request,
        "current_time": get_korea_time()
    })

@app.get("/overview", response_class=HTMLResponse)
async def overview(request: Request):
    return templates.TemplateResponse("overview.html", {
        "request": request,
        "current_time": get_korea_time()
    })

# insights 페이지
@app.get("/insights", response_class=HTMLResponse)
async def insights(request: Request):
    return templates.TemplateResponse("insights.html", {
        "request": request,
        "current_time": get_korea_time()
    })

# shadow-it 페이지
@app.get("/shadow-it", response_class=HTMLResponse)
async def shadow_it(request: Request):
    return templates.TemplateResponse("shadowit.html", {
        "request": request,
        "current_time": get_korea_time()
    })

# Db-csv 페이지
@app.get("/csvtools", response_class=HTMLResponse)
async def csv_page(request: Request):
    return templates.TemplateResponse("csvtools.html", {
        "request": request,
        "current_time": get_korea_time()
    })

# Db-csv 페이지
@app.get("/scan", response_class=HTMLResponse)
async def csv_page(request: Request):
    return templates.TemplateResponse("scan.html", {
        "request": request,
        "current_time": get_korea_time()
    })

# 개발 서버 실행
if __name__ == "__main__":
    uvicorn.run("main:app", reload=True)
