#!/bin/bash
###########################################################################
########################### 游戏服务器管理模块 #############################
# 支持 Minecraft、幻兽帕鲁 等游戏服务器的快速部署和管理

GAME_DIR="/home/game"

# ========== Minecraft 服务器管理 ==========

mc_install() {
    root_use || return 1
    clear
    echo -e "${cyan}===== 安装 Minecraft 服务器 =====${white}"

    # 检查是否已安装
    if docker ps -a --format '{{.Names}}' | grep -q '^mcserver$'; then
        echo -e "${yellow}Minecraft 服务器已存在!${white}"
        break_end
        return 1
    fi

    # 安装 Docker
    if ! command -v docker &>/dev/null; then
        install_add_docker
    fi

    echo -e "${yellow}请选择 Minecraft 版本:${white}"
    echo -e "${cyan}1.  ${white}最新正式版 (RELEASE)"
    echo -e "${cyan}2.  ${white}最新快照 (SNAPSHOT)"
    echo -e "${cyan}3.  ${white}Fabric 模组加载器"
    echo -e "${cyan}4.  ${white}Forge 模组加载器"
    read -e -p "请选择 (默认1): " mc_type
    mc_type=${mc_type:-1}

    local mc_image="itzg/minecraft-server"
    local mc_env=""

    case $mc_type in
        1) mc_env="-e EULA=true -e TYPE=VANILLA" ;;
        2) mc_env="-e EULA=true -e TYPE=SNAPSHOT" ;;
        3) mc_env="-e EULA=true -e TYPE=FABRIC" ;;
        4) mc_env="-e EULA=true -e TYPE=FORGE" ;;
        *) mc_env="-e EULA=true -e TYPE=VANILLA" ;;
    esac

    read -e -p "分配内存 (GB, 默认2): " mc_ram
    mc_ram=${mc_ram:-2}

    mkdir -p "$GAME_DIR/minecraft"

    docker run -d \
        --name mcserver \
        -p 25565:25565/tcp \
        --restart=always \
        -v "$GAME_DIR/minecraft:/data:rw" \
        -e MEMORY=${mc_ram}G \
        $mc_env \
        itzg/minecraft-server

    if [ $? -eq 0 ]; then
        echo -e "${green}Minecraft 服务器安装成功!${white}"
        echo -e "${cyan}连接地址: $(get_public_ip):25565${white}"
        echo -e "${cyan}数据目录: $GAME_DIR/minecraft${white}"
    else
        echo -e "${red}安装失败!${white}"
    fi
    break_end
}

mc_start() {
    if docker start mcserver 2>/dev/null; then
        echo -e "${green}Minecraft 服务器已启动${white}"
        mc_show_info
    else
        echo -e "${red}启动失败，请确认服务器已安装${white}"
    fi
    break_end
}

mc_stop() {
    docker stop mcserver 2>/dev/null
    echo -e "${green}Minecraft 服务器已停止${white}"
    break_end
}

mc_restart() {
    docker restart mcserver 2>/dev/null
    echo -e "${green}Minecraft 服务器已重启${white}"
    break_end
}

mc_status() {
    clear
    echo -e "${cyan}===== Minecraft 服务器状态 =====${white}"
    if docker ps -a --format '{{.Names}}' | grep -q '^mcserver$'; then
        docker ps --filter "name=mcserver" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
        echo ""
        mc_show_info
    else
        echo -e "${yellow}Minecraft 服务器未安装${white}"
    fi
    break_end
}

mc_show_info() {
    echo -e "${cyan}连接信息:${white}"
    echo -e "  地址: $(get_public_ip):25565"
    echo -e "  数据目录: $GAME_DIR/minecraft"
    echo ""
    echo -e "${cyan}容器日志 (最近10行):${white}"
    docker logs --tail 10 mcserver 2>&1
}

mc_console() {
    echo -e "${cyan}进入 Minecraft 控制台 (输入 help 查看命令, 输入 exit 退出):${white}"
    docker exec -it mcserver rcon-cli 2>/dev/null || docker attach mcserver
}

mc_backup() {
    mkdir -p "$GAME_DIR/mc_backup"
    local backup_name="mc_$(date +%Y%m%d_%H%M%S).tar.gz"
    echo -e "${cyan}正在备份 Minecraft 存档...${white}"
    docker cp mcserver:/data "$GAME_DIR/mc_backup/mc_data"
    cd "$GAME_DIR/mc_backup" && tar czf "$backup_name" mc_data
    rm -rf "$GAME_DIR/mc_backup/mc_data"
    echo -e "${green}存档已备份到: $GAME_DIR/mc_backup/$backup_name${white}"
    break_end
}

mc_restore() {
    echo -e "${yellow}可用备份:${white}"
    ls -la "$GAME_DIR/mc_backup/"*.tar.gz 2>/dev/null
    read -e -p "请输入备份文件名: " backup_file
    if [ -f "$GAME_DIR/mc_backup/$backup_file" ]; then
        docker stop mcserver 2>/dev/null
        cd "$GAME_DIR/mc_backup" && tar xzf "$backup_file"
        docker cp "$GAME_DIR/mc_backup/mc_data/." mcserver:/data/
        rm -rf "$GAME_DIR/mc_backup/mc_data"
        docker start mcserver
        echo -e "${green}存档已恢复!${white}"
    else
        echo -e "${red}备份文件不存在${white}"
    fi
    break_end
}

mc_set_cron_backup() {
    clear
    echo -e "${cyan}===== Minecraft 定时备份设置 =====${white}"
    echo -e "${cyan}1.  ${white}每天备份一次"
    echo -e "${cyan}2.  ${white}每周备份一次"
    echo -e "${cyan}3.  ${white}每小时备份一次"
    echo -e "${cyan}4.  ${white}取消定时备份"
    echo -e "${cyan}0.  ${white}返回"
    read -e -p "请选择: " cron_choice

    local backup_script='mkdir -p /home/game/mc_backup && docker cp mcserver:/data /home/game/mc_backup/mc_data && cd /home/game/mc_backup && tar czf mc_$(date +\%Y\%m\%d_\%H\%M\%S).tar.gz mc_data && rm -rf /home/game/mc_backup/mc_data'

    case $cron_choice in
        1)
            (crontab -l 2>/dev/null | grep -v "mc_backup"; echo "0 3 * * * $backup_script") | crontab -
            echo -e "${green}已设置每天凌晨3点自动备份${white}"
            ;;
        2)
            (crontab -l 2>/dev/null | grep -v "mc_backup"; echo "0 3 * * 0 $backup_script") | crontab -
            echo -e "${green}已设置每周日凌晨3点自动备份${white}"
            ;;
        3)
            (crontab -l 2>/dev/null | grep -v "mc_backup"; echo "0 * * * * $backup_script") | crontab -
            echo -e "${green}已设置每小时自动备份${white}"
            ;;
        4)
            crontab -l 2>/dev/null | grep -v "mc_backup" | crontab -
            echo -e "${green}已取消定时备份${white}"
            ;;
        0) return ;;
    esac
    break_end
}

mc_uninstall() {
    root_use || return 1
    echo -e "${red}警告: 即将卸载 Minecraft 服务器 (包括存档)!${white}"
    read -r -p "是否确认？(y/n): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        docker stop mcserver 2>/dev/null
        docker rm -f mcserver 2>/dev/null
        docker rmi -f itzg/minecraft-server 2>/dev/null
        read -r -p "是否删除存档数据？(y/n): " del_data
        if [[ "$del_data" =~ ^[Yy]$ ]]; then
            rm -rf "$GAME_DIR/minecraft"
            rm -rf "$GAME_DIR/mc_backup"
        fi
        echo -e "${green}Minecraft 服务器已卸载${white}"
    fi
    break_end
}

mc_manage() {
    while true; do
        clear
        echo -e "${cyan}===== Minecraft 服务器管理 =====${white}"
        mc_status_short
        echo ""
        echo -e "${cyan}1.   ${white}安装服务器"
        echo -e "${cyan}2.   ${white}启动"
        echo -e "${cyan}3.   ${white}停止"
        echo -e "${cyan}4.   ${white}重启"
        echo -e "${cyan}5.   ${white}查看状态/日志"
        echo -e "${cyan}6.   ${white}进入控制台"
        echo -e "${cyan}7.   ${white}备份存档"
        echo -e "${cyan}8.   ${white}恢复存档"
        echo -e "${cyan}9.   ${white}定时备份设置"
        echo -e "${cyan}10.  ${white}卸载服务器"
        echo -e "${pink}------------------------${white}"
        echo -e "${yellow}0.   ${white}返回"
        echo -e "${pink}------------------------${white}"
        read -e -p "请选择: " choice

        case $choice in
            1) mc_install ;;
            2) mc_start ;;
            3) mc_stop ;;
            4) mc_restart ;;
            5) mc_status ;;
            6) mc_console ;;
            7) mc_backup ;;
            8) mc_restore ;;
            9) mc_set_cron_backup ;;
            10) mc_uninstall ;;
            0) return ;;
            *) echo -e "${red}无效选择${white}"; sleep 1 ;;
        esac
    done
}

mc_status_short() {
    if docker ps --format '{{.Names}}' | grep -q '^mcserver$'; then
        echo -e "状态: ${green}运行中${white}  地址: $(get_public_ip):25565"
    elif docker ps -a --format '{{.Names}}' | grep -q '^mcserver$'; then
        echo -e "状态: ${yellow}已停止${white}"
    else
        echo -e "状态: ${grey}未安装${white}"
    fi
}

# ========== 幻兽帕鲁服务器管理 ==========

pal_install() {
    root_use || return 1
    clear
    echo -e "${cyan}===== 安装 幻兽帕鲁 服务器 =====${white}"

    if docker ps -a --format '{{.Names}}' | grep -q '^palworld$'; then
        echo -e "${yellow}幻兽帕鲁服务器已存在!${white}"
        break_end
        return 1
    fi

    if ! command -v docker &>/dev/null; then
        install_add_docker
    fi

    # 检查虚拟内存
    local swap_size=$(free -m | awk '/Swap:/ {print $2}')
    if [ "$swap_size" -lt 1024 ]; then
        echo -e "${yellow}建议设置至少1G虚拟内存以保证稳定运行${white}"
        read -r -p "是否现在设置？(y/n): " set_swap
        if [[ "$set_swap" =~ ^[Yy]$ ]]; then
            add_swap 2048
        fi
    fi

    read -e -p "分配内存 (GB, 默认4): " pal_ram
    pal_ram=${pal_ram:-4}

    read -e -p "服务器端口 (默认8211): " pal_port
    pal_port=${pal_port:-8211}

    mkdir -p "$GAME_DIR/palworld"

    docker run -dit \
        --name palworld \
        -p ${pal_port}:8211/udp \
        --restart=always \
        -v "$GAME_DIR/palworld:/home/steam/Steam/steamapps/common/PalServer/Pal/Saved:rw" \
        -e MEMORY=${pal_ram}G \
        -e PORT=${pal_port} \
        -e PLAYERS=32 \
        -e MULTITHREADING=true \
        -e RCON_ENABLED=true \
        -e ADMIN_PASSWORD= \
        -e SERVER_PASSWORD= \
        jammsen/palworld-dedicated-server:latest

    if [ $? -eq 0 ]; then
        echo -e "${green}幻兽帕鲁服务器安装成功!${white}"
        echo -e "${cyan}连接地址: $(get_public_ip):${pal_port}${white}"
        echo -e "${cyan}数据目录: $GAME_DIR/palworld${white}"
        echo -e "${yellow}注意: 首次启动需要较长时间下载游戏文件${white}"
    else
        echo -e "${red}安装失败!${white}"
    fi
    break_end
}

pal_start() {
    if docker start palworld 2>/dev/null; then
        echo -e "${green}幻兽帕鲁服务器已启动${white}"
        pal_show_info
    else
        echo -e "${red}启动失败${white}"
    fi
    break_end
}

pal_stop() {
    docker stop palworld 2>/dev/null
    echo -e "${green}幻兽帕鲁服务器已停止${white}"
    break_end
}

pal_restart() {
    docker restart palworld 2>/dev/null
    echo -e "${green}幻兽帕鲁服务器已重启${white}"
    break_end
}

pal_status() {
    clear
    echo -e "${cyan}===== 幻兽帕鲁 服务器状态 =====${white}"
    if docker ps -a --format '{{.Names}}' | grep -q '^palworld$'; then
        docker ps --filter "name=palworld" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
        echo ""
        pal_show_info
    else
        echo -e "${yellow}幻兽帕鲁服务器未安装${white}"
    fi
    break_end
}

pal_show_info() {
    echo -e "${cyan}连接信息:${white}"
    local port=$(docker port palworld 2>/dev/null | head -1 | cut -d: -f2)
    echo -e "  地址: $(get_public_ip):${port:-8211}"
    echo -e "  数据目录: $GAME_DIR/palworld"
    echo ""
    echo -e "${cyan}容器日志 (最近10行):${white}"
    docker logs --tail 10 palworld 2>&1
}

pal_backup() {
    mkdir -p "$GAME_DIR/pal_backup"
    local backup_name="palworld_$(date +%Y%m%d_%H%M%S).tar.gz"
    echo -e "${cyan}正在备份幻兽帕鲁存档...${white}"
    docker cp palworld:/home/steam/Steam/steamapps/common/PalServer/Pal/Saved "$GAME_DIR/pal_backup/pal_saved"
    cd "$GAME_DIR/pal_backup" && tar czf "$backup_name" pal_saved
    rm -rf "$GAME_DIR/pal_backup/pal_saved"
    echo -e "${green}存档已备份到: $GAME_DIR/pal_backup/$backup_name${white}"
    break_end
}

pal_restore() {
    echo -e "${yellow}可用备份:${white}"
    ls -la "$GAME_DIR/pal_backup/"*.tar.gz 2>/dev/null
    read -e -p "请输入备份文件名: " backup_file
    if [ -f "$GAME_DIR/pal_backup/$backup_file" ]; then
        docker stop palworld 2>/dev/null
        cd "$GAME_DIR/pal_backup" && tar xzf "$backup_file"
        docker cp "$GAME_DIR/pal_backup/pal_saved/." palworld:/home/steam/Steam/steamapps/common/PalServer/Pal/Saved/
        rm -rf "$GAME_DIR/pal_backup/pal_saved"
        docker start palworld
        echo -e "${green}存档已恢复!${white}"
    else
        echo -e "${red}备份文件不存在${white}"
    fi
    break_end
}

pal_set_cron_backup() {
    clear
    echo -e "${cyan}===== 幻兽帕鲁 定时备份设置 =====${white}"
    echo -e "${cyan}1.  ${white}每天备份一次"
    echo -e "${cyan}2.  ${white}每周备份一次"
    echo -e "${cyan}3.  ${white}取消定时备份"
    echo -e "${cyan}0.  ${white}返回"
    read -e -p "请选择: " cron_choice

    local backup_script='mkdir -p /home/game/pal_backup && docker cp palworld:/home/steam/Steam/steamapps/common/PalServer/Pal/Saved /home/game/pal_backup/pal_saved && cd /home/game/pal_backup && tar czf palworld_$(date +\%Y\%m\%d_\%H\%M\%S).tar.gz pal_saved && rm -rf /home/game/pal_backup/pal_saved'

    case $cron_choice in
        1)
            (crontab -l 2>/dev/null | grep -v "pal_backup"; echo "0 4 * * * $backup_script") | crontab -
            echo -e "${green}已设置每天凌晨4点自动备份${white}"
            ;;
        2)
            (crontab -l 2>/dev/null | grep -v "pal_backup"; echo "0 4 * * 0 $backup_script") | crontab -
            echo -e "${green}已设置每周日凌晨4点自动备份${white}"
            ;;
        3)
            crontab -l 2>/dev/null | grep -v "pal_backup" | crontab -
            echo -e "${green}已取消定时备份${white}"
            ;;
        0) return ;;
    esac
    break_end
}

pal_uninstall() {
    root_use || return 1
    echo -e "${red}警告: 即将卸载幻兽帕鲁服务器 (包括存档)!${white}"
    read -r -p "是否确认？(y/n): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        docker stop palworld 2>/dev/null
        docker rm -f palworld 2>/dev/null
        docker rmi -f jammsen/palworld-dedicated-server 2>/dev/null
        read -r -p "是否删除存档数据？(y/n): " del_data
        if [[ "$del_data" =~ ^[Yy]$ ]]; then
            rm -rf "$GAME_DIR/palworld"
            rm -rf "$GAME_DIR/pal_backup"
        fi
        echo -e "${green}幻兽帕鲁服务器已卸载${white}"
    fi
    break_end
}

pal_status_short() {
    if docker ps --format '{{.Names}}' | grep -q '^palworld$'; then
        local port=$(docker port palworld 2>/dev/null | head -1 | cut -d: -f2)
        echo -e "状态: ${green}运行中${white}  地址: $(get_public_ip):${port:-8211}"
    elif docker ps -a --format '{{.Names}}' | grep -q '^palworld$'; then
        echo -e "状态: ${yellow}已停止${white}"
    else
        echo -e "状态: ${grey}未安装${white}"
    fi
}

pal_manage() {
    while true; do
        clear
        echo -e "${cyan}===== 幻兽帕鲁 服务器管理 =====${white}"
        pal_status_short
        echo ""
        echo -e "${cyan}1.   ${white}安装服务器"
        echo -e "${cyan}2.   ${white}启动"
        echo -e "${cyan}3.   ${white}停止"
        echo -e "${cyan}4.   ${white}重启"
        echo -e "${cyan}5.   ${white}查看状态/日志"
        echo -e "${cyan}6.   ${white}备份存档"
        echo -e "${cyan}7.   ${white}恢复存档"
        echo -e "${cyan}8.   ${white}定时备份设置"
        echo -e "${cyan}9.   ${white}卸载服务器"
        echo -e "${pink}------------------------${white}"
        echo -e "${yellow}0.   ${white}返回"
        echo -e "${pink}------------------------${white}"
        read -e -p "请选择: " choice

        case $choice in
            1) pal_install ;;
            2) pal_start ;;
            3) pal_stop ;;
            4) pal_restart ;;
            5) pal_status ;;
            6) pal_backup ;;
            7) pal_restore ;;
            8) pal_set_cron_backup ;;
            9) pal_uninstall ;;
            0) return ;;
            *) echo -e "${red}无效选择${white}"; sleep 1 ;;
        esac
    done
}

# ========== 游戏服务器主菜单 ==========

linux_game_server() {
    while true; do
        clear
        echo -e "${cyan}===== 游戏服务器管理 =====${white}"
        echo -e "${cyan}1.   ${white}Minecraft 我的世界"
        echo -e "${cyan}2.   ${white}幻兽帕鲁 Palworld"
        echo -e "${pink}------------------------${white}"
        echo -e "${yellow}0.   ${white}返回主菜单"
        echo -e "${pink}------------------------${white}"
        read -e -p "请选择: " choice

        case $choice in
            1) mc_manage ;;
            2) pal_manage ;;
            0) return ;;
            *)
                echo -e "${red}${LX_invalid}${white}"
                sleep 1
                ;;
        esac
    done
}
