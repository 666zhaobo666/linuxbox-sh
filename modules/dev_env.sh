#############################################################################
############################### 九、Dev环境管理###############################
# Dev环境管理主菜单
dev_env_management() {
	while true; do
	clear
		echo -e "${green}====Dev环境管理====${white}"
		echo -e ""
		echo -e "${pink}------------------------${white}"
		echo -e "${cyan}1.${white} Python管理"
		echo -e "${cyan}2.${white} 数据库管理"
		echo -e "${cyan}3.${white} 敬请期待......"
		echo -e "${pink}------------------------${white}"
		echo -e "${yellow}0.${white} 返回主菜单"
		echo -e "${pink}------------------------${white}"

		read -e -p "请选择功能编号: " choice
		case $choice in
			1) python_management ;;
			2) db_management ;;
			0) return ;;
			*) 
				echo -e "${red}无效选择, 请重新输入 !${white}"
				sleep 1
				;;
			esac
	done
}

##############################
######### Python 管理 ########
##############################
python_management() {
    local choice
    while true; do
        clear
        echo -e "${green}Python版本管理工具${white}"
        echo -e "${pink}---------------------------------------${white}"
        echo -e "${yellow}该功能可无缝安装Python官方支持的任何版本! ${white}"

        # 获取当前Python版本
        if command -v python &>/dev/null; then
            local CURRENT_VERSION=$(python -V 2>&1 | awk '{print $2}')
        else
            local CURRENT_VERSION="未安装"
        fi
        echo -e "当前Python版本号: ${yellow}$CURRENT_VERSION${white}"
        
        echo -e "${pink}---------------------------------------${white}"
        echo -e "推荐版本:  3.12    3.11    3.10    3.9    3.8    2.7"
        echo -e "查询更多版本: https://www.python.org/downloads/"
        echo -e "${pink}---------------------------------------${white}"
        echo -e "${cyan}1.${white} 安装指定版本Python"
        echo -e "${cyan}2.${white} 切换已安装的Python版本"
        echo -e "${cyan}3.${white} 查看已安装的Python版本"
        echo -e "${cyan}4.${white} 卸载指定Python版本"
        echo -e "${yellow}0.${white} 返回上一级"
        echo -e "${pink}---------------------------------------${white}"

        read -e -p "请输入你的操作: " choice
        
        case $choice in
            1) install_python_version ;;
            2) switch_python_version ;;
            3) list_installed_versions ;;
            4) uninstall_python_version ;;
            0) 
                #  "脚本PY管理-退出"
                return ;;
            *) 
				echo -e "${red}无效选择, 请重新输入 !${white}"
				sleep 1
				;;
        esac
    done
}
# 检查并安装pyenv
ensure_pyenv_installed() {
    # 检查pyenv是否已安装
    if ! command -v pyenv &>/dev/null; then
        echo "正在安装pyenv..."
        #  "pyenv安装"
        
        # 安装依赖包
        install_pyenv_dependencies
        
        # 安装pyenv
        curl https://pyenv.run | bash
        
        # 配置环境变量
        configure_pyenv_environment
        
        # 重新加载环境变量
        source ~/.bashrc
        echo "pyenv安装完成"
    fi
}

# 安装pyenv依赖
install_pyenv_dependencies() {
    echo "正在安装必要的依赖包..."
    
    if command -v yum &>/dev/null; then
        # CentOS/RHEL系列
        yum update -y
        yum install -y git
        yum groupinstall -y "Development Tools"
        yum install -y openssl-devel bzip2-devel libffi-devel ncurses-devel \
						zlib-devel readline-devel sqlite-devel xz-devel findutils
        
        # 安装特定版本的openssl以支持较新的Python
        install_openssl
        
    elif command -v apt &>/dev/null; then
        # Debian/Ubuntu系列
        apt update -y
        apt install -y git
        apt install -y build-essential libssl-dev zlib1g-dev libbz2-dev \
						libreadline-dev libsqlite3-dev wget curl llvm \
						libncurses5-dev libncursesw5-dev xz-utils tk-dev \
						libffi-dev liblzma-dev libgdbm-dev libnss3-dev libedit-dev
        
    elif command -v apk &>/dev/null; then
        # Alpine Linux
        apk update
        apk add -y git bash gcc musl-dev libffi-dev openssl-dev bzip2-dev \
					zlib-dev readline-dev sqlite-dev libc6-compat linux-headers \
					make xz-dev build-base ncurses-dev
        
    else
        echo "错误: 未知的包管理器, 无法安装依赖"
        return 1
    fi
}

# 安装特定版本的openssl
install_openssl() {
    echo "正在安装openssl 1.1.1u..."
    curl -O https://www.openssl.org/source/openssl-1.1.1u.tar.gz
    tar -xzf openssl-1.1.1u.tar.gz
    cd openssl-1.1.1u || { echo "无法进入openssl目录"; return 1; }
    ./config --prefix=/usr/local/openssl --openssldir=/usr/local/openssl shared zlib
    make
    make install
    echo "/usr/local/openssl/lib" > /etc/ld.so.conf.d/openssl-1.1.1u.conf
    ldconfig -v
    cd ..
    
    # 配置环境变量
    export LDFLAGS="-L/usr/local/openssl/lib"
    export CPPFLAGS="-I/usr/local/openssl/include"
    export PKG_CONFIG_PATH="/usr/local/openssl/lib/pkgconfig"
    
    # 写入bashrc以便永久生效
    echo 'export LDFLAGS="-L/usr/local/openssl/lib"' >> ~/.bashrc
    echo 'export CPPFLAGS="-I/usr/local/openssl/include"' >> ~/.bashrc
    echo 'export PKG_CONFIG_PATH="/usr/local/openssl/lib/pkgconfig"' >> ~/.bashrc
}

# 配置pyenv环境变量
configure_pyenv_environment() {
    local bashrc=~/.bashrc
    
    # 检查环境变量是否已配置
    if ! grep -q 'export PYENV_ROOT="\$HOME/.pyenv"' "$bashrc"; then
        echo "配置pyenv环境变量..."
        cat << EOF >> "$bashrc"

# pyenv配置
export PYENV_ROOT="\$HOME/.pyenv"
if [[ -d "\$PYENV_ROOT/bin" ]]; then
	export PATH="\$PYENV_ROOT/bin:\$PATH"
fi
eval "\$(pyenv init --path)"
eval "\$(pyenv init -)"
eval "\$(pyenv virtualenv-init -)"
EOF
    fi
}

# 安装指定版本的Python
install_python_version() {
    #  "py版本管理-安装"
    
    read -e -p "输入你要安装的Python版本号（例如: 3.12.0, 输入0取消）: " py_new_v
    
    if [[ "$py_new_v" == "0" ]]; then
        echo "取消安装"
        sleep 1
        return
    fi
    
    # 确保pyenv已安装
    ensure_pyenv_installed || return 1
    
    echo "正在安装Python $py_new_v..."
    
    # 安装指定版本
    pyenv install "$py_new_v"
    
    # 检查安装是否成功
    if [ $? -eq 0 ]; then
        echo "设置Python $py_new_v为全局默认版本..."
        pyenv global "$py_new_v"
        
        # 清理缓存
        rm -rf /tmp/python-build.*
        rm -rf "$(pyenv root)/cache/"*
        
        # 显示当前版本
        local VERSION=$(python -V 2>&1 | awk '{print $2}')
        echo -e "安装成功! 当前Python版本号: ${yellow}$VERSION${white}"
        #  "脚本PY版本切换-$py_new_v"
    else
        echo "错误: Python $py_new_v安装失败"
    fi
    
    read -n1 -s -r -p "按任意键继续..."
}

# 切换已安装的Python版本
switch_python_version() {
    #  "py版本管理-切换"
    
    echo "已安装的Python版本:"
    pyenv versions
    
    read -e -p "输入要切换的Python版本号（输入0取消）: " py_version
    
    if [[ "$py_version" == "0" ]]; then
        echo "取消切换"
        sleep 1
        return
    fi
    
    # 检查版本是否已安装
    if ! pyenv versions | grep -q "$py_version"; then
        echo "错误: Python $py_version未安装"
        read -n1 -s -r -p "按任意键继续..."
        return 1
    fi
    
    # 切换版本
    pyenv global "$py_version"
    
    # 显示当前版本
    local VERSION=$(python -V 2>&1 | awk '{print $2}')
    echo -e "切换成功! 当前Python版本号: ${yellow}$VERSION${white}"
    #  "脚本PY版本切换-$py_version"
    
    read -n1 -s -r -p "按任意键继续..."
}

# 查看已安装的Python版本
list_installed_versions() {
    #  "py版本管理-查看已安装版本"
    
    echo "已安装的Python版本:"
    echo "---------------------"
    pyenv versions
    echo "---------------------"
    echo "* 表示当前正在使用的版本"
    
    read -n1 -s -r -p "按任意键继续..."
}

# 卸载指定Python版本
uninstall_python_version() {
    #  "py版本管理-卸载"
    
    echo "已安装的Python版本:"
    pyenv versions
    
    read -e -p "输入要卸载的Python版本号（输入0取消）: " py_version
    
    if [[ "$py_version" == "0" ]]; then
        echo "取消卸载"
        sleep 1
        return
    fi
    
    # 检查版本是否已安装
    if ! pyenv versions | grep -q "$py_version"; then
        echo "错误: Python $py_version未安装"
        read -n1 -s -r -p "按任意键继续..."
        return 1
    fi
    
    # 卸载版本
    pyenv uninstall -f "$py_version"
    
    if [ $? -eq 0 ]; then
        echo "Python $py_version已成功卸载"
        #  "脚本PY版本卸载-$py_version"
    else
        echo "错误: 卸载Python $py_version失败"
    fi
    
    read -n1 -s -r -p "按任意键继续..."
}

##############################
######### 数据库 管理 ########
##############################
db_management() {
    while true; do
		clear
		echo -e "${green}数据库管理工具${white}"
		echo -e ""
        echo -e "${pink}------------------------${white}"
        echo -e "${cyan}1.${white} MySQL数据库"
		echo -e "${cyan}2.${white} PostgreSQL数据库"
		echo -e "${cyan}3.${white} 敬请期待..."

		echo -e "${pink}------------------------${white}"
		echo -e "${yellow}0.${white} 返回主菜单"
        echo -e "${pink}------------------------${white}"

        read -e -p "请选择功能编号: " choice
        case $choice in
            1) mysql_server_app ;;
            2) postgres_server_app ;;
            0) return ;;
            *) 
				echo -e "${red}无效选择, 请重新输入 !${white}"
				sleep 1
				;;
        esac
    done
}

# MySQL数据库管理
mysql_server_app(){
    local app_id="mysql"
	local docker_name="mysql"
    local docker_img="mysql"
    local docker_port=3306
    local version=""
	# 定义常用MySQL版本
    local common_versions=("5.6" "5.7" "8.0" "latest")

    docker_run() {
		# 显示版本选择提示
		echo "常用MySQL版本:"
		for i in "${!common_versions[@]}"; do
			echo "$((i+1)). ${yellow}${common_versions[$i]}${white}"
		done

		read -e -p "请输入要安装的MySQL版本(直接输入版本号或序号):" input_version

		# 处理用户输入（支持序号或直接输入版本号）
		if [[ "$input_version" =~ ^[0-9]+$ ]] && [ $input_version -le ${#common_versions[@]} ]; then
			version=${common_versions[$((input_version-1))]}
		else
			version=$input_version
		fi

		# 根据版本生成容器名称（移除小数点）
		# local version_suffix=$(echo $version | tr -d '.')
		local version_suffix=$(echo $version)
		docker_name="${docker_name}${version_suffix}"
		app_id="${app_id}${version_suffix}"
        # 设置MySQL的root密码, 建议替换为强密码
		read -e -p "请输入MySQL数据库ROOT密码: " input_passwd
        local mysql_root_password=$input_passwd
        
        docker run -d \
			-p ${docker_port}:3306 \
            --restart=always \
            --name ${docker_name} \
            -v /home/docker/${docker_name}/data:/var/lib/mysql \
            -v /home/docker/${docker_name}/conf:/etc/mysql/conf.d \
            -v /home/docker/${docker_name}/logs:/var/log/mysql \
            -e MYSQL_ROOT_PASSWORD="${mysql_root_password}" \
            ${docker_img}:${version}
    }

	# 提取所有mysql版本号并处理格式
	local mysql_versions=""
	if [ -f /home/docker/appno.txt ]; then
		mysql_versions=$(grep -oE 'mysql.*' /home/docker/appno.txt | sed 's/mysql//' | tr '\n' ',' | sed 's/,$//')
	fi
	if [ -z "$mysql_versions" ]; then
		echo -e "${red}未安装MySQL任何版本! 即将进入安装...${white}"
		echo -e "${cyan}按回车键继续...${white}"
		read -n 1 -s -r -p ""
		clear
		docker_app
	else
		clear
		echo -e "${cyan}已安装的MySQL版本: ${white}$mysql_versions"
		read -e -p "请输入要管理的MySQL版本(直接输入版本号, 如:5.6, 如果想安装新的版本, 请直接输入 0):" version
		if [[ "$version" == "0" ]]; then
			docker_app
		elif [[ ",${mysql_versions}," == *",${version},"* ]]; then
			docker_name="${docker_name}${version}"
			app_id="${app_id}${version}"
			docker_img="${docker_img}:${version}"
			local docker_describe="MySQL Server"
			local docker_url="官网介绍: https://hub.docker.com/_/mysql"
			local docker_use=""
			local docker_passwd=""
			local app_size="1"
			docker_app
		else
			echo -e "${red}请输入正确的版本号!${white}"
			sleep 1
		fi
	fi
}

# PostgreSQL数据库管理
postgres_server_app() {
    local app_id="postgres"
    local docker_name="postgres"
    local docker_img="postgres"
    local docker_port=5432
    local version=""
    # 定义常用PostgreSQL版本
    local common_versions=("12" "13" "14" "15" "16" "latest")

    docker_run() {
        # 显示版本选择提示
        echo "常用PostgreSQL版本:"
        for i in "${!common_versions[@]}"; do
            echo "$((i+1)). ${yellow}${common_versions[$i]}${white}"
        done

        read -e -p "请输入要安装的PostgreSQL版本(直接输入版本号或序号):" input_version

        # 处理用户输入（支持序号或直接输入版本号）
        if [[ "$input_version" =~ ^[0-9]+$ ]] && [ $input_version -le ${#common_versions[@]} ]; then
            version=${common_versions[$((input_version-1))]}
        else
            version=$input_version
        fi

        # 设置容器名称和应用ID
        local version_suffix=$(echo $version)
        docker_name="${docker_name}${version_suffix}"
        app_id="${app_id}${version_suffix}"
        
        # 设置PostgreSQL的超级用户密码
        read -e -p "请输入PostgreSQL数据库postgres用户密码: " input_passwd
        local postgres_password=$input_passwd
        
        # 设置默认数据库名称
        read -e -p "请输入默认数据库名称(默认:postgres): " input_dbname
        local postgres_dbname=${input_dbname:-postgres}

        # 创建并启动PostgreSQL容器
        docker run -d \
            -p ${docker_port}:5432 \
            --restart=always \
            --name ${docker_name} \
            -v /home/docker/${docker_name}/data:/var/lib/postgresql/data \
            -v /home/docker/${docker_name}/conf:/etc/postgresql \
            -v /home/docker/${docker_name}/logs:/var/log/postgresql \
            -e POSTGRES_PASSWORD=${postgres_password} \
            -e POSTGRES_DB=${postgres_dbname} \
            ${docker_img}:${version}
        
        # 如果有需要，这里可以添加额外的配置文件修改
        # sed -i "s/PASSWORD=admin_password/PASSWORD=${admin_password}/g" /path/to/config
    }

    # 提取所有已安装的PostgreSQL版本号
    local postgres_versions=$(grep -oE 'postgres.*' /home/docker/appno.txt | sed 's/postgres//' | tr '\n' ',' | sed 's/,$//')
    if [ -z "$postgres_versions" ]; then
        echo -e "${red}未安装PostgreSQL任何版本! 即将进入安装...${white}"
        echo -e "${cyan}按回车键继续...${white}"
        read -n 1 -s -r -p ""
        clear
        docker_app
    else
        clear
        echo -e "${cyan}已安装的PostgreSQL版本: ${white}$postgres_versions"
        read -e -p "请输入要管理的PostgreSQL版本(直接输入版本号, 如:14, 如果想安装新的版本, 请直接输入 0):" version
        if [[ "$version" == "0" ]]; then
            docker_app
        elif [[ ",${postgres_versions}," == *",${version},"* ]]; then
            docker_name="${docker_name}${version}"
            app_id="${app_id}${version}"
            docker_img="${docker_img}:${version}"
            local docker_describe="PostgreSQL Server"
            local docker_url="官网介绍: https://hub.docker.com/_/postgres"
            local docker_use=""
            local docker_passwd=""
            local app_size="1"
            docker_app
        else
            echo -e "${red}请输入正确的版本号!${white}"
            sleep 1
        fi
    fi
}
