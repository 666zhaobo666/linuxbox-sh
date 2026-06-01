###########################################################################
########################### 一、系统信息查询模块 ###########################
system_info() {
	clear
    echo -e "${green}=====系统信息查询=====${white}"
    echo -e ""
    echo -e "${cyan}主机名:       ${white}$(hostname)"
    echo -e "${cyan}系统版本:     ${white}$(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
    echo -e "${cyan}Linux版本:    ${white}$(uname -r)"
    echo -e "${pink}------------------------------------------------------${white}"
    echo -e "${cyan}CPU架构:      ${white}$(uname -m)"
    echo -e "${cyan}CPU型号:      ${white}$(lscpu | grep 'Model name' | awk -F: '{print $2}' | xargs)"
    echo -e "${cyan}CPU核心数:    ${white}$(nproc)"
    echo -e "${cyan}CPU频率:      ${white}$(lscpu | grep 'MHz' | awk '{print $2/1000 " GHz"}')"
    echo -e "${pink}------------------------------------------------------${white}"
    echo -e "${cyan}CPU占用:      ${white}$(top -bn1 | grep 'Cpu(s)' | awk '{print $2}')%"
    echo -e "${cyan}系统负载:     ${white}$(uptime | awk -F'load average:' '{print $2}' | xargs)"
    echo -e "${cyan}物理内存:     ${white}$(free -m | awk '/Mem:/ {printf "%0.2f/%0.2fM (%0.2f%%)", $3, $2, $3/$2*100}')"
    echo -e "${cyan}虚拟内存:     ${white}$(free -m | awk '/Swap:/ {printf "%0.2f/%0.2fM (%0.2f%%)", $3, $2, ($2==0?0:$3/$2*100)}')"
    echo -e "${cyan}硬盘占用:     ${white}$(df -h / | awk 'NR==2{print $3"/"$2" ("$5")"}')"
    echo -e "${pink}------------------------------------------------------${white}"
    echo -e "${cyan}总接收:       ${white}$(cat /proc/net/dev | awk '/eth|ens|eno|enp|wlan/ {rx+=$2} END {printf "%.2fG", rx/1024/1024/1024}')"
    echo -e "${cyan}总发送:       ${white}$(cat /proc/net/dev | awk '/eth|ens|eno|enp|wlan/ {tx+=$10} END {printf "%.2fG", tx/1024/1024/1024}')"
    echo -e "${pink}------------------------------------------------------${white}"
    echo -e "${cyan}网络算法:     ${white}$(sysctl net.ipv4.tcp_congestion_control | awk -F= '{print $2}' | xargs)"
    echo -e "${pink}------------------------------------------------------${white}"
    echo -e "${cyan}运营商:       ${white}$(curl -s ipinfo.io/org)"
    echo -e "${cyan}IPv4地址:     ${white}$(hostname -I | awk '{print $1}')"
    echo -e "${cyan}DNS地址:      ${white}$(cat /etc/resolv.conf | grep nameserver | awk '{print $2}' | xargs)"
    echo -e "${cyan}地理位置:     ${white}$(curl -s ipinfo.io/city), $(curl -s ipinfo.io/country)"
    echo -e "${cyan}系统时间:     ${white}$(date '+%Z %Y-%m-%d %I:%M %p')"
    echo -e "${pink}------------------------------------------------------${white}"
    echo -e "${cyan}运行时长:     ${white}$(uptime -p | cut -d' ' -f2-)"
    echo -e "${pink}------------------------------------------------------${white}"
    echo -e "${green}操作完成${white}"
    break_end
    clear
}
