#############################################################################
################################ 六、防火墙管理 ##############################
# 检测防火墙类型
detect_firewall() {
    if command -v firewalld >/dev/null 2>&1; then
        echo "firewalld"
    elif command -v iptables >/dev/null 2>&1; then
        echo "iptables"
    else
        echo "none"
    fi
}

# 安装防火墙
install_firewall() {
    clear
    echo -e "${blue}===== 防火墙安装 ====="${white}
    echo "1. 安装 iptables"
    echo "2. 安装 firewalld"
    echo "0. 返回"
    echo -e "${cyan}------------------------${white}"
    read -p "请选择要安装的防火墙: " choice
    
    case $choice in
        1)
            install iptables
            install iptables-persistent 2>/dev/null  # 对于debian系
            install iptables-services 2>/dev/null    # 对于rhel系
            sudo systemctl enable iptables 2>/dev/null
            sudo systemctl start iptables 2>/dev/null
            echo -e "${green}iptables 已安装并启动${white}"
            break_end
            ;;
        2)
            install firewalld
            sudo systemctl enable firewalld
            sudo systemctl start firewalld
            echo -e "${green}firewalld 已安装并启动${white}"
            break_end
            ;;
        0)
            return
            ;;
        *)
			echo -e "${red}无效选择, 请重新输入 !${white}"
			sleep 1
			;;
    esac
}

# 卸载防火墙
uninstall_firewall() {
    local firewall=$1
    clear
    echo -e "${blue}===== 卸载 $firewall ====="${white}
    read -p "确定要卸载 $firewall 吗? (y/N) " confirm
    
    if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
        local os=$(detect_os)
        
        if [ "$firewall" = "firewalld" ]; then
            sudo systemctl stop firewalld 2>/dev/null
            sudo systemctl disable firewalld 2>/dev/null
            
            if [ "$os" = "debian" ]; then
                sudo apt remove --purge -y firewalld >/dev/null 2>&1
            elif [ "$os" = "rhel" ]; then
                if command -v dnf >/dev/null 2>&1; then
                    sudo dnf remove -y firewalld >/dev/null 2>&1
                else
                    sudo yum remove -y firewalld >/dev/null 2>&1
                fi
            elif [ "$os" = "arch" ]; then
                sudo pacman -Rns --noconfirm firewalld >/dev/null 2>&1
            fi
        elif [ "$firewall" = "iptables" ]; then
            sudo systemctl stop iptables 2>/dev/null
            sudo systemctl disable iptables 2>/dev/null
            
            if [ "$os" = "debian" ]; then
                sudo apt remove --purge -y iptables iptables-persistent >/dev/null 2>&1
            elif [ "$os" = "rhel" ]; then
                if command -v dnf >/dev/null 2>&1; then
                    sudo dnf remove -y iptables iptables-services >/dev/null 2>&1
                else
                    sudo yum remove -y iptables iptables-services >/dev/null 2>&1
                fi
            elif [ "$os" = "arch" ]; then
                sudo pacman -Rns --noconfirm iptables >/dev/null 2>&1
            fi
        fi
        
        echo -e "${green}$firewall 已卸载${white}"
    else
        echo -e "${yellow}取消卸载操作${white}"
    fi
    break_end
}

# 国家IP规则管理（依赖ipset+ipdeny.com IP库）
manage_country_rules() {
    local firewall=$1
    local action=$2
    local country=$3
    local ipset_name="country_$country"
    local ip_url="https://www.ipdeny.com/ipblocks/data/countries/$country.zone"

    # 检查ipset是否安装
    if ! command -v ipset >/dev/null 2>&1; then
        echo -e "${yellow}检测到未安装ipset, 正在安装...${white}"
        install ipset || return 1
    fi

    case $action in
        block)
            # 创建ipset集合并导入国家IP
            sudo ipset create $ipset_name hash:net 2>/dev/null
            echo -e "${cyan}正在下载$country的IP列表...${white}"
            sudo curl -s $ip_url | while read ip; do
                sudo ipset add $ipset_name $ip 2>/dev/null
            done
            
            # 应用到防火墙
            if [ "$firewall" = "firewalld" ]; then
                sudo firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source ipset=$ipset_name drop"
                sudo firewall-cmd --reload
            elif [ "$firewall" = "iptables" ]; then
                sudo iptables -A INPUT -m set --match-set $ipset_name src -j DROP
                sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null
                sudo service iptables save 2>/dev/null
            fi
            echo -e "${green}已封锁$country国家IP${white}"
            ;;
        allow)
            # 创建ipset集合并导入国家IP
            sudo ipset create $ipset_name hash:net 2>/dev/null
            echo -e "${cyan}正在下载$country的IP列表...${white}"
            sudo curl -s $ip_url | while read ip; do
                sudo ipset add $ipset_name $ip 2>/dev/null
            done
            
            # 先默认拒绝所有, 再允许国家IP+基础端口
            if [ "$firewall" = "firewalld" ]; then
                sudo firewall-cmd --permanent --set-default-zone=drop
                sudo firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source ipset=$ipset_name accept"
                local ssh_port=$(grep -E "^Port " /etc/ssh/sshd_config | awk \'{print $2}\'); ssh_port=${ssh_port:-22}; sudo firewall-cmd --permanent --add-port=${ssh_port}/tcp  # 保留SSH端口
                sudo firewall-cmd --reload
            elif [ "$firewall" = "iptables" ]; then
                sudo iptables -P INPUT DROP
                sudo iptables -A INPUT -m set --match-set $ipset_name src -j ACCEPT
                sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT  # 保留SSH端口
                sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
                sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null
                sudo service iptables save 2>/dev/null
            fi
            echo -e "${green}仅允许$country国家IP访问${white}"
            ;;
        unblock)
            # 删除关联规则
            if [ "$firewall" = "firewalld" ]; then
                sudo firewall-cmd --permanent --remove-rich-rule="rule family=ipv4 source ipset=$ipset_name drop"
                sudo firewall-cmd --permanent --remove-rich-rule="rule family=ipv4 source ipset=$ipset_name accept"
                sudo firewall-cmd --reload
            elif [ "$firewall" = "iptables" ]; then
                sudo iptables -D INPUT -m set --match-set $ipset_name src -j DROP 2>/dev/null
                sudo iptables -D INPUT -m set --match-set $ipset_name src -j ACCEPT 2>/dev/null
                sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null
                sudo service iptables save 2>/dev/null
            fi
            
            # 销毁ipset集合
            sudo ipset destroy $ipset_name 2>/dev/null
            echo -e "${green}已解除$country国家IP限制${white}"
            ;;
        *)
            echo -e "${red}无效操作(仅支持block/allow/unblock)${white}"
			sleep 1
            ;;
    esac
}

# 启动DDOS防御
enable_ddos_defense() {
    local firewall=$1
    
    case $firewall in
        firewalld)
            # 限制单IP并发连接
            sudo firewall-cmd --permanent --add-rich-rule="rule family=ipv4 port port=0-65535 protocol=tcp limit value=200/minute accept"
            sudo firewall-cmd --permanent --add-rich-rule="rule family=ipv4 port port=0-65535 protocol=udp limit value=100/minute accept"
            sudo firewall-cmd --reload
            ;;
        iptables)
            # 添加连接数限制
            sudo iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 100 -j REJECT --reject-with tcp-white
            sudo iptables -A INPUT -p tcp -m state --state NEW -m limit --limit 200/minute --limit-burst 50 -j ACCEPT
            sudo iptables -A INPUT -p udp -m state --state NEW -m limit --limit 100/minute --limit-burst 20 -j ACCEPT
            sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null
            sudo service iptables save 2>/dev/null
            ;;
    esac
    echo -e "${green}DDOS防御已启动${white}"
}

# 关闭DDOS防御
disable_ddos_defense() {
    local firewall=$1
    
    case $firewall in
        firewalld)
            sudo firewall-cmd --permanent --remove-rich-rule="rule family=ipv4 port port=0-65535 protocol=tcp limit value=200/minute accept"
            sudo firewall-cmd --permanent --remove-rich-rule="rule family=ipv4 port port=0-65535 protocol=udp limit value=100/minute accept"
            sudo firewall-cmd --reload
            ;;
        iptables)
            sudo iptables -D INPUT -p tcp --syn -m connlimit --connlimit-above 100 -j REJECT --reject-with tcp-white 2>/dev/null
            sudo iptables -D INPUT -p tcp -m state --state NEW -m limit --limit 200/minute --limit-burst 50 -j ACCEPT 2>/dev/null
            sudo iptables -D INPUT -p udp -m state --state NEW -m limit --limit 100/minute --limit-burst 20 -j ACCEPT 2>/dev/null
            sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null
            sudo service iptables save 2>/dev/null
            ;;
    esac
    echo -e "${green}DDOS防御已关闭${white}"
}

# firewalld管理面板
firewalld_panel() {
    while true; do
        clear
        echo -e "${green}===== firewalld 高级防火墙管理 =====${white}"
		echo -e ""
        echo -e "${pink}------------------------------------------------${white}"
        echo -e "${yellow}Chain INPUT (policy $(sudo firewall-cmd --get-default-zone | awk '{if ($1 == "drop") print "DROP"; else print "ACCEPT"}'))${white}"
        echo -e "${pink}------------------------------------------------${white}"

        echo -e "${cyan}1.${white} 开放指定端口                 ${cyan}2.${white} 关闭指定端口"
        echo -e "${cyan}3.${white} 开放所有端口                 ${cyan}4.${white} 关闭所有端口"
        echo -e "${pink}------------------------------------------------${white}"
        echo -e "${cyan}5.${white} IP白名单                     ${cyan}6.${white} IP黑名单"
        echo -e "${cyan}7.${white} 清除指定IP"
        echo -e "${pink}------------------------------------------------${white}"
        echo -e "${cyan}11.${white} 允许PING                     ${cyan}12.${white} 禁止PING"
        echo -e "${pink}------------------------------------------------${white}"
        echo -e "${cyan}13.${white} 启动DDOS防御                 ${cyan}14.${white} 关闭DDOS防御"
        echo -e "${pink}------------------------------------------------${white}"
        echo -e "${cyan}15.${white} 阻止指定国家IP               ${cyan}16.${white} 仅允许指定国家IP"
        echo -e "${cyan}17.${white} 解除指定国家IP限制"
        echo -e "${pink}------------------------------------------------${white}"
        echo -e "${red}99.${white} ${white}卸载防火墙${white}"
        echo -e "${yellow}0.${white} ${white}返回上一级菜单${white}"
        echo -e "${pink}------------------------------------------------${white}"
        
        read -p "请输入你的选择: " choice
        
        case $choice in
            1)  # 开放指定端口
				read -p "请输入端口号: " port
                read -p "请选择协议 (tcp/udp/all): " proto
                
                if [ "$proto" = "tcp" ] || [ "$proto" = "all" ]; then
                    sudo firewall-cmd --permanent --add-port=$port/tcp
                fi
                if [ "$proto" = "udp" ] || [ "$proto" = "all" ]; then
                    sudo firewall-cmd --permanent --add-port=$port/udp
                fi
                sudo firewall-cmd --reload
                echo -e "${green}端口 $port ($proto) 已开放${white}"
                break_end
                ;;
                
            2)  # 关闭指定端口
                read -p "请输入端口号: " port
                read -p "请选择协议 (tcp/udp/all): " proto
                
                if [ "$proto" = "tcp" ] || [ "$proto" = "all" ]; then
                    sudo firewall-cmd --permanent --remove-port=$port/tcp
                fi
                if [ "$proto" = "udp" ] || [ "$proto" = "all" ]; then
                    sudo firewall-cmd --permanent --remove-port=$port/udp
                fi
                sudo firewall-cmd --reload
                echo -e "${green}端口 $port ($proto) 已关闭${white}"
                break_end
                ;;
                
            3)  # 开放所有端口
                sudo firewall-cmd --permanent --set-default-zone=public
                sudo firewall-cmd --permanent --zone=public --add-rich-rule='rule family=ipv4 source address=0.0.0.0/0 accept'
                sudo firewall-cmd --reload
                echo -e "${yellow}警告: 已开放所有端口, 安全性降低${white}"
                break_end
                ;;
                
            4)  # 关闭所有端口
                sudo firewall-cmd --permanent --set-default-zone=drop
                sudo firewall-cmd --reload
                echo -e "${green}已设置默认拒绝所有流量${white}"
                break_end
                ;;
                
            5)  # IP白名单
                read -p "请输入允许的IP/IP段 (如192.168.1.0/24): " ip
                sudo firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$ip accept"
                sudo firewall-cmd --reload
                echo -e "${green}IP $ip 已添加到白名单${white}"
                break_end
                ;;
                
            6)  # IP黑名单
                read -p "请输入禁止的IP/IP段 (如192.168.1.0/24): " ip
                sudo firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$ip drop"
                sudo firewall-cmd --reload
                echo -e "${green}IP $ip 已添加到黑名单${white}"
                break_end
                ;;
                
            7)  # 清除指定IP
                read -p "请输入要清除规则的IP/IP段: " ip
                sudo firewall-cmd --permanent --remove-rich-rule="rule family=ipv4 source address=$ip accept" 2>/dev/null
                sudo firewall-cmd --permanent --remove-rich-rule="rule family=ipv4 source address=$ip drop" 2>/dev/null
                sudo firewall-cmd --reload
                echo -e "${green}IP $ip 的规则已清除${white}"
                break_end
                ;;
                
            11)  # 允许PING
                sudo firewall-cmd --permanent --remove-icmp-block=echo-request
                sudo firewall-cmd --reload
                echo -e "${green}已允许PING${white}"
                break_end
                ;;
                
            12)  # 禁止PING
                sudo firewall-cmd --permanent --add-icmp-block=echo-request
                sudo firewall-cmd --reload
                echo -e "${green}已禁止PING${white}"
                break_end
                ;;
                
            13)  # 启动DDOS防御
                enable_ddos_defense "firewalld"
                break_end
                ;;
                
            14)  # 关闭DDOS防御
                disable_ddos_defense "firewalld"
                break_end
                ;;
                
            15)  # 阻止指定国家IP
                read -p "请输入国家代码 (如CN/US, 大写): " country
                manage_country_rules "firewalld" "block" $country
                break_end
                ;;
                
            16)  # 仅允许指定国家IP
                read -p "请输入国家代码 (如CN/US, 大写): " country
                manage_country_rules "firewalld" "allow" $country
                break_end
                ;;
                
            17)  # 解除指定国家IP限制
                read -p "请输入国家代码 (如CN/US, 大写): " country
                manage_country_rules "firewalld" "unblock" $country
                break_end
                ;;
                
            99)  # 卸载防火墙
                uninstall_firewall "firewalld"
                return
                ;;
			0)  # 返回上一级
				return 1
				;;
                
            *)
				echo -e "${red}无效选择, 请重新输入 !${white}"
				sleep 1
				;;
        esac
    done
}

# iptables管理面板
iptables_panel() {
    while true; do
        clear
        echo -e "${green}===== iptables 高级防火墙管理 ====="${white}
        echo -e ""
        echo -e "${pink}------------------------------------------------${white}"
        echo -e "${yellow}Chain INPUT (policy $(sudo iptables -L INPUT -n | head -n 1 | awk '{print $4}'))${white}"
        echo -e "${pink}------------------------------------------------${white}"

        echo -e "${cyan}1.${white} 开放指定端口                 ${cyan}2.${white} 关闭指定端口"
        echo -e "${cyan}3.${white} 开放所有端口                 ${cyan}4.${white} 关闭所有端口"
        echo -e "${pink}------------------------------------------------${white}"
        echo -e "${cyan}5.${white} IP白名单                     ${cyan}6.${white} IP黑名单"
        echo -e "${cyan}7.${white} 清除指定IP"
        echo -e "${pink}------------------------------------------------${white}"
        echo -e "${cyan}11.${white} 允许PING                     ${cyan}12.${white} 禁止PING"
        echo -e "${pink}------------------------------------------------${white}"
        echo -e "${cyan}13.${white} 启动DDOS防御                 ${cyan}14.${white} 关闭DDOS防御"
        echo -e "${pink}------------------------------------------------${white}"
        echo -e "${cyan}15.${white} 阻止指定国家IP               ${cyan}16.${white} 仅允许指定国家IP"
        echo -e "${cyan}17.${white} 解除指定国家IP限制"
		echo -e "${pink}------------------------------------------------${white}"
        echo -e "${red}99.${white} ${white}卸载防火墙${white}"
        echo -e "${yellow}0.${white} ${white}返回上一级菜单${white}"
        echo -e "${pink}------------------------------------------------${white}"
        
        read -p "请输入你的选择: " choice
        
        case $choice in
            1)  # 开放指定端口
                read -p "请输入端口号: " port
                read -p "请选择协议 (tcp/udp/all): " proto
                
                if [ "$proto" = "tcp" ] || [ "$proto" = "all" ]; then
                    sudo iptables -A INPUT -p tcp --dport $port -j ACCEPT
                fi
                if [ "$proto" = "udp" ] || [ "$proto" = "all" ]; then
                    sudo iptables -A INPUT -p udp --dport $port -j ACCEPT
                fi
                sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null
                sudo service iptables save 2>/dev/null
                echo -e "${green}端口 $port ($proto) 已开放${white}"
                break_end
                ;;
                
            2)  # 关闭指定端口
                read -p "请输入端口号: " port
                read -p "请选择协议 (tcp/udp/all): " proto
                
                if [ "$proto" = "tcp" ] || [ "$proto" = "all" ]; then
                    sudo iptables -D INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null
                    sudo iptables -A INPUT -p tcp --dport $port -j DROP
                fi
                if [ "$proto" = "udp" ] || [ "$proto" = "all" ]; then
                    sudo iptables -D INPUT -p udp --dport $port -j ACCEPT 2>/dev/null
                    sudo iptables -A INPUT -p udp --dport $port -j DROP
                fi
                sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null
                sudo service iptables save 2>/dev/null
                echo -e "${green}端口 $port ($proto) 已关闭${white}"
                break_end
                ;;
                
            3)  # 开放所有端口
                sudo iptables -P INPUT ACCEPT
                sudo iptables -F INPUT
                sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null
                sudo service iptables save 2>/dev/null
                echo -e "${yellow}警告: 已开放所有端口, 安全性降低${white}"
                break_end
                ;;
                
            4)  # 关闭所有端口
                sudo iptables -P INPUT DROP
                # 保留已建立的连接
                sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
                sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null
                sudo service iptables save 2>/dev/null
                echo -e "${green}已设置默认拒绝所有流量${white}"
                break_end
                ;;
                
            5)  # IP白名单
                read -p "请输入允许的IP/IP段 (如192.168.1.0/24): " ip
                sudo iptables -A INPUT -s $ip -j ACCEPT
                sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null
                sudo service iptables save 2>/dev/null
                echo -e "${green}IP $ip 已添加到白名单${white}"
                break_end
                ;;
                
            6)  # IP黑名单
                read -p "请输入禁止的IP/IP段 (如192.168.1.0/24): " ip
                sudo iptables -A INPUT -s $ip -j DROP
                sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null
                sudo service iptables save 2>/dev/null
                echo -e "${green}IP $ip 已添加到黑名单${white}"
                break_end
                ;;
                
            7)  # 清除指定IP
                read -p "请输入要清除规则的IP/IP段: " ip
                # 删除所有与该IP相关的规则
                while sudo iptables -D INPUT -s $ip -j ACCEPT 2>/dev/null; do :; done
                while sudo iptables -D INPUT -s $ip -j DROP 2>/dev/null; do :; done
                sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null
                sudo service iptables save 2>/dev/null
                echo -e "${green}IP $ip 的规则已清除${white}"
                break_end
                ;;
                
            11)  # 允许PING
                sudo iptables -D INPUT -p icmp --icmp-type echo-request -j DROP 2>/dev/null
                sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
                sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null
                sudo service iptables save 2>/dev/null
                echo -e "${green}已允许PING${white}"
                break_end
                ;;
                
            12)  # 禁止PING
                sudo iptables -D INPUT -p icmp --icmp-type echo-request -j ACCEPT 2>/dev/null
                sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
                sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null
                sudo service iptables save 2>/dev/null
                echo -e "${green}已禁止PING${white}"
                break_end
                ;;
                
            13)  # 启动DDOS防御
                enable_ddos_defense "iptables"
                break_end
                ;;
                
            14)  # 关闭DDOS防御
                disable_ddos_defense "iptables"
                break_end
                ;;
                
            15)  # 阻止指定国家IP
                read -p "请输入国家代码 (如CN/US, 大写): " country
                manage_country_rules "iptables" "block" $country
                break_end
                ;;
                
            16)  # 仅允许指定国家IP
                read -p "请输入国家代码 (如CN/US, 大写): " country
                manage_country_rules "iptables" "allow" $country
                break_end
                ;;
                
            17)  # 解除指定国家IP限制
                read -p "请输入国家代码 (如CN/US, 大写): " country
                manage_country_rules "iptables" "unblock" $country
                break_end
                ;;
			99)  # 卸载防火墙
                uninstall_firewall "iptables"
                return
                ;;
                
            0)  # 返回上一级
				return 1
				;;
                
            *)
				echo -e "${red}无效选择, 请重新输入 !${white}"
				sleep 1
				;;
        esac
    done
}

# 主防火墙管理函数
linux_firewall() {
    while true; do
        local firewall=$(detect_firewall)
        
        if [ "$firewall" = "none" ]; then
            clear
            echo -e "${green}===== 防火墙管理 =====${white}"
            echo -e "${red}未检测到已安装的防火墙${white}"
            echo "1. 安装 iptables"
            echo "2. 安装 firewalld"
            echo "0. 退出"
            echo -e "${cyan}------------------------${white}"
            read -p "请选择操作: " choice
            
            case $choice in
                1)
                    install_firewall
                    ;;
                2)
                    install_firewall
                    ;;
                0)
                    return
                    ;;
                *)
					echo -e "${red}无效选择, 请重新输入 !${white}"
					sleep 1
					;;
            esac
        else
            # 根据检测到的防火墙类型进入相应的管理面板
            if [ "$firewall" = "firewalld" ]; then
                firewalld_panel || break
            elif [ "$firewall" = "iptables" ]; then
                iptables_panel || break
            fi
        fi
    done
}
