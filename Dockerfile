FROM kalilinux/kali-rolling
ENV DEBIAN_FRONTEND=noninteractive
# 默认环境变量，可在 docker build/run 时覆盖
ENV PIP_BREAK_SYSTEM_PACKAGES=1 \
    GOPROXY="https://goproxy.cn,direct" \
    PIP_INDEX_URL="https://pypi.tuna.tsinghua.edu.cn/simple" \
    NUCLEI_TEMPLATES="/root/nuclei-templates"

# 1) 换源（阿里）+ 更新
RUN printf "deb http://mirrors.aliyun.com/kali kali-rolling main non-free contrib non-free-firmware\n" \
    > /etc/apt/sources.list \
 && apt-get update

# 2) 安装必须软件（python3/pip3/go/渗透工具/pcap 等）
RUN apt-get install -y --no-install-recommends \
      python3 python3-pip python3-venv \
      git curl wget jq ca-certificates \
      nmap sqlmap wpscan nikto whatweb gobuster dirb feroxbuster dirsearch \
      amass sslyze testssl.sh wafw00f joomscan \
      golang make build-essential pkg-config \
      libpcap-dev libpcap0.8 ffuf \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 3) 安装 Python requirements（提前缓存层）
COPY requirements.txt /app/requirements.txt
RUN python3 -m pip install -U pip -i "$PIP_INDEX_URL" \
 && pip3 install -r /app/requirements.txt -i "$PIP_INDEX_URL"

# 4) COPY extras-installer 源码目录并执行安装器
COPY extras-installer/ /app/extras-installer/
RUN chmod +x /app/extras-installer/extras-install.sh \
 && /app/extras-installer/extras-install.sh

# 5) 复制经常变动的应用代码
# COPY kali_server.py /app/kali_server.py
COPY mcp_server.py  /app/mcp_server.py
COPY config.json    /app/config.json

EXPOSE 8080
CMD ["uvicorn", "mcp_server:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
