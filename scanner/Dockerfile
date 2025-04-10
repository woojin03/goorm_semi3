# Python 3.10-slim을 베이스 이미지로 사용합니다.
FROM python:3.10-slim

# 패키지 업데이트 후 nmap 설치 및 캐시 정리
RUN apt-get update && \
    apt-get install -y nmap && \
    rm -rf /var/lib/apt/lists/*

# 작업 디렉토리 설정
WORKDIR /app

# 현재 디렉토리의 모든 파일들을 컨테이너 내부 /app 디렉토리에 복사
COPY scanner_test2.py ./  
COPY .env ./  
COPY config.json ./
COPY requirements.txt ./

# 필요한 파이썬 패키지 설치
RUN pip install --no-cache-dir -r requirements.txt

# 컨테이너 실행 시 스캐너를 실행
CMD ["python", "scanner.py"]
