#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import random
import time
import shutil
import re
import base64
import socket
import subprocess
import platform
from datetime import datetime
import uuid
from pathlib import Path
import ssl
import tempfile
import argparse

# 尝试导入 requests 库
try:
    import requests
except ImportError:
    print("错误: Python 'requests' 库未安装。")
    print("请先运行: pip install requests")
    sys.exit(1)

# 全局变量 - 使用新的目录以避免与旧版本冲突
INSTALL_DIR = Path.home() / ".agsb-secure"
CONFIG_FILE = INSTALL_DIR / "config.json"
SB_PID_FILE = INSTALL_DIR / "sbpid.log"
ARGO_PID_FILE = INSTALL_DIR / "argopid.log"
LIST_FILE = INSTALL_DIR / "list.txt"
LOG_FILE = INSTALL_DIR / "argo.log"
DEBUG_LOG = INSTALL_DIR / "python_debug.log"
CLOUDFLARED_CONFIG_YML = INSTALL_DIR / "config.yml"

# ====== 全局可配置参数 ======
# 这些值现在主要作为后备，推荐通过交互式输入或命令行参数提供
DEFAULT_TUNNEL_NAME = "agsb-named-tunnel"
DEFAULT_UUID = "" # 留空则自动生成
DEFAULT_PORT = 49999 # Vmess端口，留空或0则自动生成
DEFAULT_DOMAIN = "" # 必须由用户提供
DEFAULT_SUBDOMAIN = "" # 必须由用户提供
DEFAULT_API_TOKEN = "" # 必须由用户提供
# =========================================

# --- 辅助函数 ---

def print_info(secure_mode=False):
    title = "✨ ArgoSB Python3 - 安全隧道版 ✨" if secure_mode else "✨ ArgoSB Python3 ✨"
    print("\033[36m╭───────────────────────────────────────────────────────────────╮\033[0m")
    print(f"\033[36m│             \033[33m{title:^43}\033[36m│\033[0m")
    print("\033[36m├───────────────────────────────────────────────────────────────┤\033[0m")
    print("\033[36m│ \033[32m此版本经过修改，使用命名隧道 (Named Tunnel) 以隐藏源IP。\033[36m│\033[0m")
    print("\033[36m│ \033[32m确保您的匿名性和安全性，工作方式与 install.sh 脚本一致。\033[36m│\033[0m")
    print("\033[36m╰───────────────────────────────────────────────────────────────╯\033[0m")

def run_command(command, capture_output=False, text=True, check=True):
    """一个封装好的函数，用于运行外部命令"""
    try:
        write_debug_log(f"执行命令: {' '.join(command)}")
        result = subprocess.run(command, capture_output=capture_output, text=text, check=check)
        write_debug_log(f"命令执行完毕。返回码: {result.returncode}")
        if capture_output:
            write_debug_log(f"STDOUT: {result.stdout.strip()}")
            write_debug_log(f"STDERR: {result.stderr.strip()}")
        return result
    except FileNotFoundError:
        print(f"\033[31m错误: 命令 '{command[0]}' 未找到。请确保它已安装并且在您的 PATH 中。\033[0m")
        write_debug_log(f"命令未找到错误: {command[0]}")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"\033[31m命令执行失败: {' '.join(command)}\033[0m")
        print(f"错误信息: {e.stderr}")
        write_debug_log(f"命令执行失败: {e}")
        raise

def write_debug_log(message):
    try:
        INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        with open(DEBUG_LOG, 'a', encoding='utf-8') as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        print(f"写入日志失败: {e}")

def get_required_input(prompt, env_var=None, default_val=None):
    val = os.environ.get(env_var) if env_var else None
    if val:
        return val
    val = default_val or ""
    user_input = input(f"{prompt} (默认: {val}): ").strip()
    return user_input or val


# --- 核心修改逻辑 ---

def setup_named_tunnel(config):
    """完整的命名隧道设置流程，包括登录、创建、配置和DNS更新"""
    print("\n\033[33m--- 开始设置安全命名隧道 (Step 1/4) ---\033[0m")
    
    # 1. 登录 Cloudflare
    print("1. 检查 Cloudflare 授权...")
    cert_path = Path.home() / ".cloudflared" / "cert.pem"
    if not cert_path.exists():
        print("未检测到授权文件，将打开浏览器进行登录授权...")
        run_command(['cloudflared', 'tunnel', 'login'])
        if not cert_path.exists():
            print("\033[31m登录失败或未完成授权，脚本无法继续。\033[0m")
            sys.exit(1)
    else:
        print("授权文件已存在，跳过登录。")

    # 2. 清理并创建隧道
    print("\n\033[33m--- 开始创建隧道 (Step 2/4) ---\033[0m")
    tunnel_name = config['tunnel_name']
    print(f"2. 检查并创建名为 '{tunnel_name}' 的隧道...")
    
    # 检查隧道是否存在
    result = run_command(['cloudflared', 'tunnel', 'list'], capture_output=True)
    if tunnel_name in result.stdout:
        print(f"警告: 名为 '{tunnel_name}' 的隧道已存在，将删除重建以确保配置正确。")
        run_command(['cloudflared', 'tunnel', 'delete', tunnel_name])

    # 创建新隧道
    result = run_command(['cloudflared', 'tunnel', 'create', tunnel_name], capture_output=True)
    
    # 从输出中解析 Tunnel ID 和凭证文件路径
    match_id = re.search(r'Tunnel credentials written to (.+?\.json).*with id ([a-f0-9-]+)', result.stderr)
    if not match_id:
        print("\033[31m创建隧道失败，无法解析Tunnel ID和凭证文件。\033[0m")
        sys.exit(1)
        
    creds_file_path = Path(match_id.group(1).strip())
    tunnel_id = match_id.group(2).strip()
    config['tunnel_id'] = tunnel_id
    config['creds_file'] = str(creds_file_path)
    print(f"隧道创建成功! ID: {tunnel_id}")

    # 3. 生成 cloudflared 的 config.yml
    print("\n\033[33m--- 生成配置文件 (Step 3/4) ---\033[0m")
    print("3. 生成 cloudflared 的 'config.yml'...")
    
    yml_content = f"""
tunnel: {tunnel_id}
credentials-file: {creds_file_path}

ingress:
  - hostname: {config['subdomain']}
    service: http://127.0.0.1:{config['port_vm_ws']}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
"""
    CLOUDFLARED_CONFIG_YML.write_text(yml_content)
    print(f"'config.yml' 已保存到 {CLOUDFLARED_CONFIG_YML}")
    
    # 4. 更新 DNS 记录
    print("\n\033[33m--- 更新DNS记录 (Step 4/4) ---\033[0m")
    print("4. 使用 Cloudflare API 更新 CNAME 记录...")
    update_dns_record(config)

def update_dns_record(config):
    """使用Python requests库更新DNS记录"""
    api_token = config['api_token']
    domain = config['domain']
    subdomain = config['subdomain']
    tunnel_id = config['tunnel_id']
    
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }
    
    # 获取 Zone ID
    try:
        response = requests.get(f"https://api.cloudflare.com/client/v4/zones?name={domain}", headers=headers)
        response.raise_for_status()
        zone_id = response.json()['result'][0]['id']
        print(f"获取 Zone ID 成功: {zone_id}")
    except (requests.RequestException, IndexError, KeyError) as e:
        print(f"\033[31m获取 Zone ID 失败: {e}\033[0m")
        print("请检查您的根域名和API Token是否正确。")
        sys.exit(1)
        
    # 检查DNS记录是否存在
    cname_content = f"{tunnel_id}.cfargotunnel.com"
    try:
        response = requests.get(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=CNAME&name={subdomain}", headers=headers)
        response.raise_for_status()
        records = response.json()['result']
    except requests.RequestException as e:
        print(f"\033[31m获取DNS记录失败: {e}\033[0m")
        sys.exit(1)

    if records:
        # 更新记录
        record_id = records[0]['id']
        print(f"找到已存在的 CNAME 记录，将进行更新。Record ID: {record_id}")
        url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
        data = {"type": "CNAME", "name": subdomain, "content": cname_content, "ttl": 1, "proxied": True}
        response = requests.put(url, headers=headers, json=data)
    else:
        # 创建记录
        print("未找到 CNAME 记录，将创建新记录。")
        url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
        data = {"type": "CNAME", "name": subdomain, "content": cname_content, "ttl": 1, "proxied": True}
        response = requests.post(url, headers=headers, json=data)
        
    try:
        if response.json()['success']:
            print("\033[32m✅ DNS CNAME 记录更新/创建成功！\033[0m")
        else:
            print(f"\033[31mDNS 更新失败: {response.text}\033[0m")
            sys.exit(1)
    except (requests.RequestException, KeyError) as e:
        print(f"\033[31m处理DNS响应时出错: {e}\033[0m")
        sys.exit(1)

def create_sing_box_config(port_vm_ws, uuid_str):
    """与原版一致，但确保路径正确"""
    ws_path = f"/{uuid_str[:8]}-vm"
    config_dict = {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [{
            "type": "vmess", "listen": "127.0.0.1", "listen_port": port_vm_ws,
            "users": [{"uuid": uuid_str, "alterId": 0}],
            "transport": {"type": "ws", "path": ws_path}
        }],
        "outbounds": [{"type": "direct"}]
    }
    sb_config_file = INSTALL_DIR / "sb.json"
    sb_config_file.write_text(json.dumps(config_dict, indent=2))

def create_startup_script():
    """重构此函数以使用 config.yml"""
    # sing-box 启动脚本 (无变化)
    sb_start_script_path = INSTALL_DIR / "start_sb.sh"
    sb_start_content = f"#!/bin/bash\ncd {INSTALL_DIR.resolve()}\n./sing-box run -c sb.json > sb.log 2>&1 &\necho $! > {SB_PID_FILE.name}\n"
    sb_start_script_path.write_text(sb_start_content)
    os.chmod(sb_start_script_path, 0o755)

    # cloudflared 启动脚本 (核心修改)
    cf_start_script_path = INSTALL_DIR / "start_cf.sh"
    cf_cmd = f"./cloudflared --config {CLOUDFLARED_CONFIG_YML.resolve()} tunnel run"
    
    cf_start_content = f"#!/bin/bash\ncd {INSTALL_DIR.resolve()}\n{cf_cmd} > {LOG_FILE.name} 2>&1 &\necho $! > {ARGO_PID_FILE.name}\n"
    cf_start_script_path.write_text(cf_start_content)
    os.chmod(cf_start_script_path, 0o755)
    
    write_debug_log("安全的启动脚本已创建/更新。")

def generate_links(subdomain, port_vm_ws, uuid_str):
    """生成最终的VMess链接，与原版类似但使用确定的子域名"""
    ws_path = f"/{uuid_str[:8]}-vm"
    ws_path_full = f"{ws_path}?ed=2048"
    
    config = {
        "v": "2", "ps": f"AGSB-Secure-{subdomain}", "add": subdomain, "port": "443",
        "id": uuid_str, "aid": "0", "net": "ws", "type": "none",
        "host": subdomain, "path": ws_path_full, "tls": "tls", "sni": subdomain
    }
    
    vmess_str = json.dumps(config, sort_keys=True)
    vmess_b64 = base64.b64encode(vmess_str.encode('utf-8')).decode('utf-8').rstrip("=")
    vmess_link = f"vmess://{vmess_b64}"
    
    # 打印最终信息
    print("\033[36m╭───────────────────────────────────────────────────────────────╮\033[0m")
    print("\033[36m│                \033[33m✨ ArgoSB 安全隧道部署成功! ✨            \033[36m│\033[0m")
    print("\033[36m├───────────────────────────────────────────────────────────────┤\033[0m")
    print(f"\033[36m│ \033[32m地址 (Address): \033[0m{subdomain}")
    print(f"\033[36m│ \033[32m端口 (Port): \033[0m443")
    print(f"\033[36m│ \033[32m用户ID (UUID): \033[0m{uuid_str}")
    print(f"\033[36m│ \033[32m传输 (Network): \033[0mws")
    print(f"\033[36m│ \033[32m路径 (Path): \033[0m{ws_path_full}")
    print(f"\033[36m│ \033[32mTLS: \033[0mtls")
    print("\033[36m├───────────────────────────────────────────────────────────────┤\033[0m")
    print(f"\033[36m│ \033[33mVMess 链接: \033[0m{vmess_link}")
    print("\033[36m╰───────────────────────────────────────────────────────────────╯\033[0m")
    
    # 保存信息到文件
    (INSTALL_DIR / "allnodes.txt").write_text(vmess_link + "\n")
    LIST_FILE.write_text(f"VMess链接: {vmess_link}\n配置域名: {subdomain}\n")
    
    return True

# --- 主安装流程 ---

def install():
    """重构的主安装函数"""
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    os.chdir(INSTALL_DIR)
    
    print("\n\033[33m--- 开始配置安全隧道参数 ---\033[0m")
    config = {}
    config['domain'] = get_required_input("请输入您的 Cloudflare 根域名 (例如: example.com)", "CF_DOMAIN", DEFAULT_DOMAIN)
    config['subdomain'] = get_required_input(f"请输入您要使用的子域名 (例如: proxy.{config['domain']})", "CF_SUBDOMAIN", f"proxy.{config['domain']}")
    config['api_token'] = get_required_input("请输入 Cloudflare API Token (具有DNS编辑权限)", "CF_API_TOKEN", DEFAULT_API_TOKEN)
    config['uuid_str'] = get_required_input("请输入自定义UUID (留空则随机生成)", "UUID", str(uuid.uuid4()))
    config['tunnel_name'] = DEFAULT_TUNNEL_NAME

    try:
        port_str = get_required_input(f"请输入本地 Vmess 端口 (10000-65535，留空则随机)", "PORT", str(random.randint(20000, 50000)))
        config['port_vm_ws'] = int(port_str)
    except ValueError:
        config['port_vm_ws'] = random.randint(20000, 50000)

    if not all([config['domain'], config['subdomain'], config['api_token']]):
        print("\033[31m错误: 根域名、子域名和API Token 均为必填项。\033[0m")
        sys.exit(1)
        
    # 下载二进制文件
    # (此部分逻辑与原版基本一致，为简洁省略，可直接从原脚本拷贝或假设已存在)
    print("\n\033[33m--- 检查/下载所需程序 ---\033[0m")
    if not (INSTALL_DIR / "cloudflared").exists():
        arch = "amd64" if "x86_64" in platform.machine() else "arm64"
        url = f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{arch}"
        print("正在下载 cloudflared...")
        run_command(['wget', '-O', 'cloudflared', url])
        os.chmod(INSTALL_DIR / "cloudflared", 0o755)

    if not (INSTALL_DIR / "sing-box").exists():
        print("sing-box 下载逻辑省略，请确保已手动放置或从原脚本拷贝此部分。")
        # 为能运行，此处放置一个简化的下载
        arch = "amd64" if "x86_64" in platform.machine() else "arm64"
        ver = "1.9.1"
        url = f"https://github.com/SagerNet/sing-box/releases/download/v{ver}/sing-box-{ver}-linux-{arch}.tar.gz"
        print("正在下载 sing-box...")
        run_command(['wget', '-O', 'sing-box.tar.gz', url])
        run_command(['tar', '-xzf', 'sing-box.tar.gz'])
        shutil.move(f'sing-box-{ver}-linux-{arch}/sing-box', INSTALL_DIR / 'sing-box')
        os.chmod(INSTALL_DIR / "sing-box", 0o755)
    
    # 核心安装流程
    setup_named_tunnel(config)
    create_sing_box_config(config['port_vm_ws'], config['uuid_str'])
    create_startup_script()
    
    print("\n\033[33m--- 启动服务 ---\033[0m")
    # 停止旧服务
    if SB_PID_FILE.exists(): os.system(f"kill $(cat {SB_PID_FILE}) 2>/dev/null")
    if ARGO_PID_FILE.exists(): os.system(f"kill $(cat {ARGO_PID_FILE}) 2>/dev/null")
    
    # 启动新服务
    run_command(['bash', str(INSTALL_DIR / "start_sb.sh")])
    run_command(['bash', str(INSTALL_DIR / "start_cf.sh")])
    time.sleep(5)
    print("服务已启动。")
    
    # 生成并显示最终链接
    generate_links(config['subdomain'], config['port_vm_ws'], config['uuid_str'])
    
    # 保存最终配置
    CONFIG_FILE.write_text(json.dumps(config, indent=2))

def main():
    print_info(secure_mode=True)
    # 简化主逻辑，直接进入安装
    install()

if __name__ == "__main__":
    main()
