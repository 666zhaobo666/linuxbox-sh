#!/bin/bash
###########################################################################
########################### 系统工具扩展 ###################################
# 包含升级管理、版本回滚等功能

# 升级管理菜单
update_management_menu() {
    while true; do
        clear
        echo -e "${green}===== 脚本升级管理 =====${white}"
        echo ""
        echo -e "${cyan}当前版本: ${green}${version}${white}"
        echo ""
        echo -e "${pink}------------------------${white}"
        echo -e "${cyan}1.  ${white}检查并更新到最新版本"
        echo -e "${cyan}2.  ${white}查看更新日志"
        echo -e "${cyan}3.  ${white}版本回滚"
        echo -e "${cyan}4.  ${white}查看备份列表"
        echo -e "${cyan}5.  ${white}清理旧备份"
        echo -e "${pink}------------------------${white}"
        echo -e "${yellow}0.  ${white}返回"
        echo -e "${pink}------------------------${white}"
        read -e -p "请选择: " choice

        case $choice in
            1)
                update_script
                ;;
            2)
                view_changelog
                ;;
            3)
                rollback_version
                ;;
            4)
                list_backups
                ;;
            5)
                clean_old_backups
                ;;
            0)
                return
                ;;
            *)
                echo -e "${red}无效选择${white}"
                sleep 1
                ;;
        esac
    done
}

# 列出备份
list_backups() {
    clear
    echo -e "${cyan}===== 备份列表 =====${white}"

    if [ ! -d "${SCRIPT_HOME}/backup" ] || [ -z "$(ls -A "${SCRIPT_HOME}/backup" 2>/dev/null)" ]; then
        echo -e "${yellow}没有可用的备份${white}"
        break_end
        return 1
    fi

    local i=1
    echo -e "${cyan}序号  备份时间              版本           大小${white}"
    echo -e "${pink}------------------------------------------------${white}"

    ls -t "${SCRIPT_HOME}/backup/" | while read -r backup; do
        local backup_path="${SCRIPT_HOME}/backup/${backup}"
        local backup_version="unknown"
        local backup_size="0"

        if [ -f "${backup_path}/LinuxBox.sh" ]; then
            backup_version=$(grep '^version=' "${backup_path}/LinuxBox.sh" | head -n 1 | cut -d '"' -f 2)
        fi

        if [ -d "$backup_path" ]; then
            backup_size=$(du -sh "$backup_path" 2>/dev/null | cut -f1)
        fi

        printf "%-5s %-20s %-14s %s\n" "$i" "$backup" "$backup_version" "$backup_size"
        i=$((i + 1))
    done

    echo ""
    break_end
}

# 清理旧备份
clean_old_backups() {
    clear
    echo -e "${cyan}===== 清理旧备份 =====${white}"

    local backup_count
    backup_count=$(ls -1 "${SCRIPT_HOME}/backup/" 2>/dev/null | wc -l)

    if [ "$backup_count" -eq 0 ]; then
        echo -e "${yellow}没有备份需要清理${white}"
        break_end
        return 1
    fi

    echo -e "当前共有 ${cyan}${backup_count}${white} 个备份"
    echo ""
    read -e -p "保留最近几个备份？(默认保留5个): " keep_count
    keep_count=${keep_count:-5}

    if [ "$keep_count" -lt 1 ]; then
        echo -e "${red}至少需要保留1个备份${white}"
        break_end
        return 1
    fi

    if [ "$backup_count" -le "$keep_count" ]; then
        echo -e "${yellow}备份数量(${backup_count})未超过保留数量(${keep_count})，无需清理${white}"
        break_end
        return 0
    fi

    local delete_count=0
    ls -t "${SCRIPT_HOME}/backup/" | tail -n +$((keep_count + 1)) | while read -r old_backup; do
        rm -rf "${SCRIPT_HOME}/backup/${old_backup}"
        echo -e "${grey}已删除: ${old_backup}${white}"
        delete_count=$((delete_count + 1))
    done

    echo ""
    echo -e "${green}✓ 清理完成，保留了最近 ${keep_count} 个备份${white}"
    break_end
}

# 查看模块版本信息
show_module_info() {
    clear
    echo -e "${cyan}===== 模块信息 =====${white}"
    echo ""
    echo -e "${cyan}脚本版本: ${green}${version}${white}"
    echo -e "${cyan}安装目录: ${LINUXBOX_LIB_DIR}${white}"
    echo -e "${cyan}配置目录: ${SCRIPT_HOME}${white}"
    echo ""

    echo -e "${cyan}Lib 目录文件:${white}"
    for file in "${LINUXBOX_LIB_DIR}"/lib/*.sh; do
        if [ -f "$file" ]; then
            local filename
            filename=$(basename "$file")
            local lines
            lines=$(wc -l < "$file")
            printf "  %-25s %5s 行\n" "$filename" "$lines"
        fi
    done

    echo ""
    echo -e "${cyan}Modules 目录文件:${white}"
    for file in "${LINUXBOX_LIB_DIR}"/modules/*.sh; do
        if [ -f "$file" ]; then
            local filename
            filename=$(basename "$file")
            local lines
            lines=$(wc -l < "$file")
            printf "  %-25s %5s 行\n" "$filename" "$lines"
        fi
    done

    echo ""
    echo -e "${cyan}总代码行数:${white}"
    find "${LINUXBOX_LIB_DIR}" -name "*.sh" -exec wc -l {} + | tail -1

    break_end
}
