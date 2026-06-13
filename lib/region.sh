detect_region() {
    if ! command -v curl >/dev/null 2>&1; then
        return 1
    fi

    # 尝试通过IP解析服务获取地区代码
    # 使用多个服务提高可靠性
    local ip_services=(
        "https://ipapi.co/country/"
        "https://ipinfo.io/country"
        "https://api.ip.sb/country"
    )
    
    for service in "${ip_services[@]}"; do
        # 超时3秒, 静默模式获取地区代码
        local country
        country=$(curl -s --connect-timeout 3 "$service" | tr '[:lower:]' '[:upper:]')
        if [ -n "$country" ] && [ ${#country} -eq 2 ]; then
            region="$country"
            return 0
        fi
    done
    
    # 所有服务失败时使用默认值
    return 1
}
## url加速服务
use_proxy(){
    # 先检测并更新地区
    detect_region || true
    
    if [ "$region" == "CN" ]; then
        url_proxy="https://proxy.cccg.top/"
    else
        url_proxy="https://"
    fi
	gh_proxy="$url_proxy"
	gh_https_url="https://"
	LINUXBOX_PROXY_READY=1
}

init_proxy_defaults() {
    if [ "$region" == "CN" ]; then
        url_proxy="${url_proxy:-https://proxy.cccg.top/}"
    else
        url_proxy="${url_proxy:-https://}"
    fi
	gh_proxy="${gh_proxy:-$url_proxy}"
	gh_https_url="${gh_https_url:-https://}"
}

ensure_proxy() {
	if [ "${LINUXBOX_PROXY_READY:-0}" != "1" ]; then
		use_proxy
	fi
}
load_linuxbox_config
init_proxy_defaults


# 脚本地址
script_url="${url_proxy}raw.githubusercontent.com/${SCRIPT_REPO_OWNER}/${SCRIPT_REPO_NAME}/${SCRIPT_BRANCH}/LinuxBox.sh"
