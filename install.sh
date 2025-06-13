#!/bin/bash
set -e

# ==============================================================================
# Cloudflare Tunnel & Sing-Box 非 Root 用户一键部署脚本
# ==============================================================================
# 说明:
# 1. 此脚本为非 root 用户设计，所有文件将安装在 $HOME/cftunnel 目录下。
# 2. 脚本会自动下载 cloudflared 和 sing-box，无需手动安装。
# 3. 脚本会以后台进程方式运行服务，而非 systemd 服务。
# ==============================================================================

# --- 基础配置 ---
BASE_DIR="$HOME/cftunnel"
BIN_DIR="${BASE_DIR}/bin"
CONFIG_DIR="${BASE_DIR}/config"
LOG_DIR="${BASE_DIR}/logs"
PID_DIR="${BASE_DIR}/pids"
TUNNEL_NAME="socks-tunnel-user" # 使用一个新名称以避免与 root 环境冲突

# --- 确保脚本路径为最新 ---
export PATH="${BIN_DIR}:${PATH}"

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ==============================================================================
# 函数定义
# ==============================================================================

# --- 检查依赖 ---
check_dependencies() {
    echo -e "${YELLOW}📦 正在检查依赖...${NC}"
    local missing_deps=0
    for cmd in curl wget unzip qrencode jq; do
        if ! command -v "$cmd" &> /dev/null; then
            echo -e "${RED}❌ 错误: 命令 '$cmd' 未找到。${NC}"
            missing_deps=1
        fi
    done

    if [ "$missing_deps" -eq 1 ]; then
        echo -e "${RED}请先使用 sudo apt update && sudo apt install -y curl wget unzip qrencode jq 安装所需依赖。${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ 所有依赖均已安装。${NC}"
}

# --- 停止现有服务 ---
stop_existing_services() {
    echo -e "${YELLOW}🛑 正在检查并停止旧的后台服务...${NC}"
    if [ -f "${PID_DIR}/cloudflared.pid" ]; then
        pid=$(cat "${PID_DIR}/cloudflared.pid")
        if ps -p "$pid" > /dev/null; then
            echo "   - 正在停止旧的 cloudflared (PID: $pid)..."
            kill "$pid" || true
        fi
        rm -f "${PID_DIR}/cloudflared.pid"
    fi

    if [ -f "${PID_DIR}/sb.pid" ]; then
        pid=$(cat "${PID_DIR}/sb.pid")
        if ps -p "$pid" > /dev/null; then
            echo "   - 正在停止旧的 sing-box (PID: $pid)..."
            kill "$pid" || true
        fi
        rm -f "${PID_DIR}/sb.pid"
    fi
    echo -e "${GREEN}✅ 旧服务已清理。${NC}"
}

# --- 安装程序 ---
install_binaries() {
    echo -e "${YELLOW}📥 正在安装 cloudflared 和 sing-box...${NC}"
    
    # 安装 cloudflared
    echo "   - 下载 cloudflared..."
    wget -O "${BIN_DIR}/cloudflared" https://github.com/cloudflare/cloudflare-warp/releases/latest/download/cloudflared-linux-amd64
    chmod +x "${BIN_DIR}/cloudflared"

    # 安装 sing-box
    echo "   - 下载 sing-box..."
    ARCH=$(uname -m)
    SING_BOX_VERSION="1.8.5" # 您可以按需更改版本
    case "$ARCH" in
      x86_64) PLATFORM="linux-amd64" ;;
      aarch64) PLATFORM="linux-arm64" ;;
      armv7l) PLATFORM="linux-armv7" ;;
      *) echo -e "${RED}❌ 不支持的架构: $ARCH${NC}"; exit 1 ;;
    esac
    
    local temp_dir=$(mktemp -d)
    curl -Lo "${temp_dir}/sing-box.tar.gz" "https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/sing-box-${SING_BOX_VERSION}-${PLATFORM}.tar.gz"
    tar -zxf "${temp_dir}/sing-box.tar.gz" -C "$temp_dir"
    cp "${temp_dir}/sing-box-${SING_BOX_VERSION}-${PLATFORM}/sing-box" "${BIN_DIR}/sb"
    chmod +x "${BIN_DIR}/sb"
    rm -rf "$temp_dir"
    
    echo -e "${GREEN}✅ cloudflared 和 sing-box 安装完成。${NC}"
}

# --- 更新DNS记录 ---
update_dns_record() {
    echo -e "${YELLOW}🌐 正在更新 Cloudflare DNS 记录...${NC}"
    
    TUNNEL_ID=$(cloudflared tunnel list | grep "$TUNNEL_NAME" | awk '{print $1}')
    if [ -z "$TUNNEL_ID" ]; then
        echo -e "${RED}❌ 获取 Tunnel ID 失败！${NC}"
        return 1
    fi

    echo "   - 获取 Zone ID..."
    ZONE_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$CF_DOMAIN" \
      -H "Authorization: Bearer $CF_API_TOKEN" \
      -H "Content-Type: application/json" | jq -r '.result[0].id')

    if [ -z "$ZONE_ID" ] || [ "$ZONE_ID" == "null" ]; then
      echo -e "${RED}❌ 获取 Zone ID 失败，请检查根域名是否正确或 API Token 权限。${NC}"
      exit 1
    fi
    echo "   - Zone ID: $ZONE_ID"

    echo "   - 获取 DNS Record ID..."
    DNS_RECORD_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?type=CNAME&name=$CF_SUBDOMAIN" \
      -H "Authorization: Bearer $CF_API_TOKEN" \
      -H "Content-Type: application/json" | jq -r '.result[0].id')

    if [ -z "$DNS_RECORD_ID" ] || [ "$DNS_RECORD_ID" == "null" ]; then
      echo -e "${YELLOW}⚠️ CNAME 记录不存在，将尝试创建新记录...${NC}"
      RESPONSE=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
        -H "Authorization: Bearer $CF_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data '{
          "type": "CNAME",
          "name": "'"$CF_SUBDOMAIN"'",
          "content": "'"$TUNNEL_ID"'.cfargotunnel.com",
          "ttl": 1,
          "proxied": true
        }')
    else
        echo "   - DNS Record ID: $DNS_RECORD_ID"
        echo "   - 正在更新已存在的 CNAME 记录..."
        RESPONSE=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$DNS_RECORD_ID" \
          -H "Authorization: Bearer $CF_API_TOKEN" \
          -H "Content-Type: application/json" \
          --data '{
            "type": "CNAME",
            "name": "'"$CF_SUBDOMAIN"'",
            "content": "'"$TUNNEL_ID"'.cfargotunnel.com",
            "ttl": 1,
            "proxied": true
          }')
    fi

    SUCCESS=$(echo "$RESPONSE" | jq -r '.success')
    if [ "$SUCCESS" == "true" ]; then
      echo -e "${GREEN}✅ CNAME 记录更新/创建成功！${NC}"
    else
      echo -e "${RED}❌ 更新失败，返回信息: $RESPONSE${NC}"
      exit 1
    fi
}

# ==============================================================================
# 主执行流程
# ==============================================================================

# --- 步骤 0: 初始化和用户输入 ---
clear
echo "============================================================"
echo "      Cloudflare Tunnel & Sing-Box 非 Root 用户部署脚本"
echo "============================================================"
echo "此脚本将在您的用户目录下创建 '$BASE_DIR' 并安装所有组件。"
echo

check_dependencies

echo
read -p "请输入您的 Cloudflare 根域名 (例如: example.com): " CF_DOMAIN
read -p "请输入您要使用的子域名 (例如: mysocks.$CF_DOMAIN): " CF_SUBDOMAIN
read -s -p "请输入您的 Cloudflare API Token: " CF_API_TOKEN
echo
echo

# --- 步骤 1: 创建目录结构 ---
echo -e "${YELLOW}🚧 正在创建工作目录...${NC}"
mkdir -p "$BIN_DIR" "$CONFIG_DIR" "$LOG_DIR" "$PID_DIR"
echo -e "${GREEN}✅ 目录已创建: $BASE_DIR ${NC}"

# --- 步骤 2: 清理旧进程和安装 ---
stop_existing_services
install_binaries

# --- 步骤 3: Cloudflare 授权和 Tunnel 创建 ---
echo -e "${YELLOW}🔑 Cloudflare 授权与 Tunnel 配置...${NC}"
if [ ! -f "$HOME/.cloudflared/cert.pem" ]; then
    echo "   - 浏览器将打开，请登录并授权 Cloudflare..."
    cloudflared tunnel login
else
    echo "   - 已检测到存在的授权文件，跳过登录。"
fi

echo "   - 检查已存在的 Tunnel: '$TUNNEL_NAME'..."
if cloudflared tunnel list | grep -Fq "$TUNNEL_NAME"; then
    echo "   - ⚠️ Tunnel '$TUNNEL_NAME' 已存在，正在删除..."
    cloudflared tunnel delete "$TUNNEL_NAME"
fi

echo "   - 正在创建新的 Tunnel: $TUNNEL_NAME ..."
cloudflared tunnel create "$TUNNEL_NAME"
TUNNEL_ID=$(cloudflared tunnel list | grep "$TUNNEL_NAME" | awk '{print $1}')
TUNNEL_CRED_FILE=$(find "$HOME/.cloudflared/" -name "${TUNNEL_ID}.json")

if [ -z "$TUNNEL_CRED_FILE" ]; then
    echo -e "${RED}❌ 找不到 Tunnel 凭证文件！脚本终止。${NC}"
    exit 1
fi

# --- 步骤 4: 生成配置文件 ---
echo -e "${YELLOW}⚙️ 正在生成配置文件...${NC}"
# 生成 sing-box 配置文件
NEW_UUID=$(cat /proc/sys/kernel/random/uuid)
cat <<EOF > "${CONFIG_DIR}/sb_config.json"
{
  "log": { "level": "info", "timestamp": true },
  "dns": { "servers": [{ "address": "8.8.8.8" }, { "address": "1.1.1.1" }] },
  "inbounds": [
    {
      "type": "vless",
      "listen": "127.0.0.1",
      "listen_port": 2080,
      "users": [
        { "uuid": "${NEW_UUID}", "flow": "" }
      ],
      "transport": { "type": "ws", "path": "/" }
    }
  ],
  "outbounds": [{ "type": "direct" }]
}
EOF
echo "   - sing-box 配置 (sb_config.json) 已生成，使用随机 UUID。"

# 生成 cloudflared 配置文件
cp "$TUNNEL_CRED_FILE" "${CONFIG_DIR}/${TUNNEL_ID}.json"
cat <<EOF > "${CONFIG_DIR}/config.yml"
tunnel: $TUNNEL_ID
credentials-file: ${CONFIG_DIR}/${TUNNEL_ID}.json

ingress:
  - hostname: ${CF_SUBDOMAIN}
    service: http://127.0.0.1:2080
    originRequest:
      noTLSVerify: true
  - service: http_status:404
EOF
echo "   - cloudflared 配置 (config.yml) 已生成。"

# --- 步骤 5: 更新 DNS ---
update_dns_record

# --- 步骤 6: 启动服务 ---
echo -e "${YELLOW}🚀 正在启动后台服务...${NC}"
# 启动 sing-box
nohup "${BIN_DIR}/sb" run -c "${CONFIG_DIR}/sb_config.json" > "${LOG_DIR}/sing-box.log" 2>&1 &
echo $! > "${PID_DIR}/sb.pid"
echo "   - sing-box 已启动, PID: $(cat ${PID_DIR}/sb.pid), 日志: ${LOG_DIR}/sing-box.log"

# 启动 cloudflared
nohup "${BIN_DIR}/cloudflared" --config "${CONFIG_DIR}/config.yml" tunnel run > "${LOG_DIR}/cloudflared.log" 2>&1 &
echo $! > "${PID_DIR}/cloudflared.pid"
echo "   - cloudflared 已启动, PID: $(cat ${PID_DIR}/cloudflared.pid), 日志: ${LOG_DIR}/cloudflared.log"

sleep 5 # 等待服务稳定

# --- 步骤 7: 完成 ---
echo
echo -e "${GREEN}🎉🎉🎉 安装配置全部完成! 🎉🎉🎉${NC}"
echo "============================================================"
echo "您的 VLESS 代理信息如下:"
echo "------------------------------------------------------------"
echo -e "地址 (Address):   ${CF_SUBDOMAIN}"
echo -e "端口 (Port):      443"
echo -e "用户ID (UUID):    ${NEW_UUID}"
echo -e "加密 (Security):  none"
echo -e "传输方式 (Network): ws (websocket)"
echo -e "路径 (Path):      /"
echo -e "TLS:              tls"
echo "============================================================"
echo
echo "📱 扫描下方二维码导入配置 (vless://...):"

VLESS_LINK="vless://${NEW_UUID}@${CF_SUBDOMAIN}:443?encryption=none&security=tls&type=ws&path=%2F#${TUNNEL_NAME}"
qrencode -t ANSIUTF8 "$VLESS_LINK"
echo
echo -e "${YELLOW}重要提示:${NC}"
echo -e "  - 服务已在后台运行。您可以通过 'ps aux | grep cloudflared' 和 'ps aux | grep sb' 查看进程。"
echo -e "  - 要停止服务，请运行 'kill \$(cat ${PID_DIR}/cloudflared.pid)' 和 'kill \$(cat ${PID_DIR}/sb.pid)'"
echo -e "  - 建议创建一个 'stop.sh' 脚本以便于管理。"
echo "============================================================"
