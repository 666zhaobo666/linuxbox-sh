detect_region() {
    # 尝试通过IP解析服务获取地区代码
    # 使用多个服务提高可靠性
    local ip_services=(
        "https://ipapi.co/country/"
        "https://ipinfo.io/country"
        "https://api.ip.sb/country"
    )
    
    for service in "${ip_services[@]}"; do
        # 超时3秒, 静默模式获取地区代码
        local country=$(curl -s --connect-timeout 3 "$service" | tr '[:lower:]' '[:upper:]')
        if [ -n "$country" ] && [ ${#country} -eq 2 ]; then
            region="$country"
            echo "检测到地区: $region"
            return 0
        fi
    done
    
    # 所有服务失败时使用默认值
    echo "无法检测地区, 使用默认值: $region"
    return 1
}
## url加速服务
use_proxy(){
    # 先检测并更新地区
    detect_region
    
    if [ "$region" == "CN" ]; then
        url_proxy="https://proxy.cccg.top/"
    else
        url_proxy="https://"
    fi
	gh_proxy="$url_proxy"
	gh_https_url="https://"
}
load_linuxbox_config
use_proxy


# 脚本地址
script_url="${url_proxy}raw.githubusercontent.com/${SCRIPT_REPO_OWNER}/${SCRIPT_REPO_NAME}/${SCRIPT_BRANCH}/modular/LinuxBox.sh"
