#############################################################################
############################### 五、LDNMP建站管理 ############################
# 版本信息
ldnmp_v() {
	# 获取nginx版本
	local nginx_version=$(docker exec nginx nginx -v 2>&1)
	local nginx_version=$(echo "$nginx_version" | grep -oP "nginx/\K[0-9]+\.[0-9]+\.[0-9]+")
	echo -n -e "nginx : ${yellow}v$nginx_version${white}"

	# 获取mysql版本
	local dbrootpasswd=$(grep -oP 'MYSQL_ROOT_PASSWORD:\s*\K.*' /home/web/docker-compose.yml | tr -d '[:space:]')
	local mysql_version=$(docker exec mysql mysql -u root -p"$dbrootpasswd" -e "SELECT VERSION();" 2>/dev/null | tail -n 1)
	echo -n -e "            mysql : ${yellow}v$mysql_version${white}"

	# 获取php版本
	local php_version=$(docker exec php php -v 2>/dev/null | grep -oP "PHP \K[0-9]+\.[0-9]+\.[0-9]+")
	echo -n -e "            php : ${yellow}v$php_version${white}"

	# 获取redis版本
	local redis_version=$(docker exec redis redis-server -v 2>&1 | grep -oP "v=+\K[0-9]+\.[0-9]+")
	echo -e "            redis : ${yellow}v$redis_version${white}"

	echo "------------------------"
	echo ""
}

# 修复PHP-FPM配置
fix_phpfpm_conf() {
	local container_name=$1
	docker exec "$container_name" sh -c "mkdir -p /run/$container_name && chmod 777 /run/$container_name"
	docker exec "$container_name" sh -c "sed -i '1i [global]\\ndaemonize = no' /usr/local/etc/php-fpm.d/www.conf"
	docker exec "$container_name" sh -c "sed -i '/^listen =/d' /usr/local/etc/php-fpm.d/www.conf"
	docker exec "$container_name" sh -c "echo -e '\nlisten = /run/$container_name/php-fpm.sock\nlisten.owner = www-data\nlisten.group = www-data\nlisten.mode = 0777' >> /usr/local/etc/php-fpm.d/www.conf"
	docker exec "$container_name" sh -c "rm -f /usr/local/etc/php-fpm.d/zz-docker.conf"

	find /home/web/conf.d/ -type f -name "*.conf" -exec sed -i "s#fastcgi_pass ${container_name}:9000;#fastcgi_pass unix:/run/${container_name}/php-fpm.sock;#g" {} \;
}

# 安装LDNMP配置
install_ldnmp_conf() {
	# 创建必要的目录和文件
	cd /home && mkdir -p web/html web/mysql web/certs web/conf.d web/redis web/log/nginx && touch web/docker-compose.yml
	wget -O /home/web/nginx.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/nginx10.conf
	wget -O /home/web/conf.d/default.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/default10.conf
	wget -O /home/web/redis/valkey.conf ${gh_proxy}raw.githubusercontent.com/kejilion/sh/main/valkey.conf


	default_server_ssl

	# 下载 docker-compose.yml 文件并进行替换
	wget -O /home/web/docker-compose.yml ${gh_proxy}raw.githubusercontent.com/kejilion/docker/main/LNMP-docker-compose-10.yml
	dbrootpasswd=$(openssl rand -base64 16) ; dbuse=$(openssl rand -hex 4) ; dbusepasswd=$(openssl rand -base64 8)

	# 在 docker-compose.yml 文件中进行替换
	sed -i "s#webroot#$dbrootpasswd#g" /home/web/docker-compose.yml
	sed -i "s#kejilionYYDS#$dbusepasswd#g" /home/web/docker-compose.yml
	sed -i "s#kejilion#$dbuse#g" /home/web/docker-compose.yml
}

# 安装LDNMP
install_ldnmp() {
	check_swap
	cp /home/web/docker-compose.yml /home/web/docker-compose1.yml

	if ! grep -q "network_mode" /home/web/docker-compose.yml; then
	wget -O /home/web/docker-compose.yml ${gh_proxy}raw.githubusercontent.com/kejilion/docker/main/LNMP-docker-compose-10.yml
	dbrootpasswd=$(grep -oP 'MYSQL_ROOT_PASSWORD:\s*\K.*' /home/web/docker-compose1.yml | tr -d '[:space:]')
	dbuse=$(grep -oP 'MYSQL_USER:\s*\K.*' /home/web/docker-compose1.yml | tr -d '[:space:]')
	dbusepasswd=$(grep -oP 'MYSQL_PASSWORD:\s*\K.*' /home/web/docker-compose1.yml | tr -d '[:space:]')

	sed -i "s#webroot#$dbrootpasswd#g" /home/web/docker-compose.yml
	sed -i "s#kejilionYYDS#$dbusepasswd#g" /home/web/docker-compose.yml
	sed -i "s#kejilion#$dbuse#g" /home/web/docker-compose.yml

	fi

	if grep -q "kjlion/nginx:alpine" /home/web/docker-compose1.yml; then
	sed -i 's|kjlion/nginx:alpine|nginx:alpine|g' /home/web/docker-compose.yml  > /dev/null 2>&1
	sed -i 's|nginx:alpine|kjlion/nginx:alpine|g' /home/web/docker-compose.yml  > /dev/null 2>&1
	fi

	cd /home/web && docker compose up -d
	sleep 1
	crontab -l 2>/dev/null | grep -v 'logrotate' | crontab -
	(crontab -l 2>/dev/null; echo '0 2 * * * docker exec nginx apk add logrotate && docker exec nginx logrotate -f /etc/logrotate.conf') | crontab -

	fix_phpfpm_conf php
	fix_phpfpm_conf php74
	restart_ldnmp


	clear
	echo "LDNMP环境安装完毕"
	echo "------------------------"
	ldnmp_v
}

# 安装Certbot
install_certbot() {
	cd ~
	curl -sS -O ${gh_proxy}raw.githubusercontent.com/kejilion/sh/main/auto_cert_renewal.sh
	chmod +x auto_cert_renewal.sh

	check_crontab_installed
	local cron_job="0 0 * * * ~/auto_cert_renewal.sh"
	crontab -l 2>/dev/null | grep -vF "$cron_job" | crontab -
	(crontab -l 2>/dev/null; echo "$cron_job") | crontab -
	echo "续签任务已更新"
}

# 安装SSL/TLS
install_ssltls() {
	docker stop nginx > /dev/null 2>&1
	check_port > /dev/null 2>&1
	cd ~

	local file_path="/etc/letsencrypt/live/$yuming/fullchain.pem"
	if [ ! -f "$file_path" ]; then
		local ipv4_pattern='^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
		local ipv6_pattern='^(([0-9A-Fa-f]{1,4}:){1,7}:|([0-9A-Fa-f]{1,4}:){7,7}[0-9A-Fa-f]{1,4}|::1)$'
		# local ipv6_pattern='^([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}$'
		# local ipv6_pattern='^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?))|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?))|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?))|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?))))$'
		if [[ ($yuming =~ $ipv4_pattern || $yuming =~ $ipv6_pattern) ]]; then
			mkdir -p /etc/letsencrypt/live/$yuming/
			if command -v dnf &>/dev/null || command -v yum &>/dev/null; then
				openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout /etc/letsencrypt/live/$yuming/privkey.pem -out /etc/letsencrypt/live/$yuming/fullchain.pem -days 5475 -subj "/C=US/ST=State/L=City/O=Organization/OU=Organizational Unit/CN=Common Name"
			else
				openssl genpkey -algorithm Ed25519 -out /etc/letsencrypt/live/$yuming/privkey.pem
				openssl req -x509 -key /etc/letsencrypt/live/$yuming/privkey.pem -out /etc/letsencrypt/live/$yuming/fullchain.pem -days 5475 -subj "/C=US/ST=State/L=City/O=Organization/OU=Organizational Unit/CN=Common Name"
			fi
		else
			docker run -it --rm -p 80:80 -v /etc/letsencrypt/:/etc/letsencrypt certbot/certbot certonly --standalone -d "$yuming" --email your@email.com --agree-tos --no-eff-email --force-renewal --key-type ecdsa
		fi
	fi
	mkdir -p /home/web/certs/
	cp /etc/letsencrypt/live/$yuming/fullchain.pem /home/web/certs/${yuming}_cert.pem > /dev/null 2>&1
	cp /etc/letsencrypt/live/$yuming/privkey.pem /home/web/certs/${yuming}_key.pem > /dev/null 2>&1

	docker start nginx > /dev/null 2>&1
}


# 证书信息
install_ssltls_text() {
	echo -e "${yellow}$yuming 公钥信息${white}"
	cat /etc/letsencrypt/live/$yuming/fullchain.pem
	echo ""
	echo -e "${yellow}$yuming 私钥信息${white}"
	cat /etc/letsencrypt/live/$yuming/privkey.pem
	echo ""
	echo -e "${yellow}证书存放路径${white}"
	echo "公钥: /etc/letsencrypt/live/$yuming/fullchain.pem"
	echo "私钥: /etc/letsencrypt/live/$yuming/privkey.pem"
	echo ""
}

# 添加SSL证书
add_ssl() {
	echo -e "${yellow}快速申请SSL证书, 过期前自动续签${white}"
	yuming="${1:-}"
	if [ -z "$yuming" ]; then
		add_yuming
	fi
	install_docker
	install_certbot
	docker run -it --rm -v /etc/letsencrypt/:/etc/letsencrypt certbot/certbot delete --cert-name "$yuming" -n 2>/dev/null
	install_ssltls
	certs_status
	install_ssltls_text
	ssl_ps
}

# 证书到期情况
ssl_ps() {
	echo -e "${yellow}已申请的证书到期情况${white}"
	echo "站点信息                      证书到期时间"
	echo "------------------------"
	for cert_dir in /etc/letsencrypt/live/*; do
		local cert_file="$cert_dir/fullchain.pem"
		if [ -f "$cert_file" ]; then
			local domain=$(basename "$cert_dir")
			local expire_date=$(openssl x509 -noout -enddate -in "$cert_file" | awk -F'=' '{print $2}')
			local formatted_date=$(date -d "$expire_date" '+%Y-%m-%d')
			printf "%-30s%s\n" "$domain" "$formatted_date"
		fi
	done
	echo ""
}



# 默认服务器 SSL
default_server_ssl() {
	install openssl
	if command -v dnf &>/dev/null || command -v yum &>/dev/null; then
		openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout /home/web/certs/default_server.key -out /home/web/certs/default_server.crt -days 5475 -subj "/C=US/ST=State/L=City/O=Organization/OU=Organizational Unit/CN=Common Name"
	else
		openssl genpkey -algorithm Ed25519 -out /home/web/certs/default_server.key
		openssl req -x509 -key /home/web/certs/default_server.key -out /home/web/certs/default_server.crt -days 5475 -subj "/C=US/ST=State/L=City/O=Organization/OU=Organizational Unit/CN=Common Name"
	fi
	openssl rand -out /home/web/certs/ticket12.key 48
	openssl rand -out /home/web/certs/ticket13.key 80
}

# 证书状态
certs_status() {
	sleep 1
	local file_path="/etc/letsencrypt/live/$yuming/fullchain.pem"
	if [ -f "$file_path" ]; then
		echo "域名证书申请成功"
	else
		# "域名证书申请失败"
		echo -e "${red}注意: ${white}证书申请失败, 请检查以下可能原因并重试："
		echo -e "1. 域名拼写错误 ➠ 请检查域名输入是否正确"
		echo -e "2. DNS解析问题 ➠ 确认域名已正确解析到本服务器IP"
		echo -e "3. 网络配置问题 ➠ 如使用Cloudflare Warp等虚拟网络请暂时关闭"
		echo -e "4. 防火墙限制 ➠ 检查80/443端口是否开放, 确保验证可访问"
		echo -e "5. 申请次数超限 ➠ Let's Encrypt有每周限额(5次/域名/周)"
		echo -e "6. 国内备案限制 ➠ 中国大陆环境请确认域名是否备案"
		break_end
		clear
		echo "请再次尝试部署 $webname"
		add_yuming
		install_ssltls
		certs_status
	fi
}

# 重复添加域名
repeat_add_yuming() {
	if [ -e /home/web/conf.d/$yuming.conf ]; then
		# "域名重复使用"
		web_del "${yuming}" > /dev/null 2>&1
	fi
}

# 添加域名
add_yuming() {
	ip_address
	echo -e "先将域名解析到本机IP: ${yellow}$ipv4_address  $ipv6_address${white}"
	read -e -p "请输入你的IP或者解析过的域名: " yuming
}

# 添加数据库
add_db() {
	dbname=$(echo "$yuming" | sed -e 's/[^A-Za-z0-9]/_/g')
	dbname="${dbname}"

	dbrootpasswd=$(grep -oP 'MYSQL_ROOT_PASSWORD:\s*\K.*' /home/web/docker-compose.yml | tr -d '[:space:]')
	dbuse=$(grep -oP 'MYSQL_USER:\s*\K.*' /home/web/docker-compose.yml | tr -d '[:space:]')
	dbusepasswd=$(grep -oP 'MYSQL_PASSWORD:\s*\K.*' /home/web/docker-compose.yml | tr -d '[:space:]')
	docker exec mysql mysql -u root -p"$dbrootpasswd" -e "CREATE DATABASE $dbname; GRANT ALL PRIVILEGES ON $dbname.* TO \"$dbuse\"@\"%\";"
}

# 反向代理
reverse_proxy() {
	ip_address
	wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/reverse-proxy.conf
	sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
	sed -i "s/0.0.0.0/$ipv4_address/g" /home/web/conf.d/$yuming.conf
	sed -i "s|0000|$duankou|g" /home/web/conf.d/$yuming.conf
	nginx_http_on
	docker exec nginx nginx -s reload
}

# 重启 Redis
restart_redis() {
	rm -rf /home/web/redis/*
	docker exec redis redis-cli FLUSHALL > /dev/null 2>&1
	# docker exec -it redis redis-cli CONFIG SET maxmemory 1gb > /dev/null 2>&1
	# docker exec -it redis redis-cli CONFIG SET maxmemory-policy allkeys-lru > /dev/null 2>&1
}


# 重启 LDNMP
restart_ldnmp() {
	restart_redis
	docker exec nginx chown -R nginx:nginx /var/www/html > /dev/null 2>&1
	docker exec nginx mkdir -p /var/cache/nginx/proxy > /dev/null 2>&1
	docker exec nginx mkdir -p /var/cache/nginx/fastcgi > /dev/null 2>&1
	docker exec nginx chown -R nginx:nginx /var/cache/nginx/proxy > /dev/null 2>&1
	docker exec nginx chown -R nginx:nginx /var/cache/nginx/fastcgi > /dev/null 2>&1
	docker exec php chown -R www-data:www-data /var/www/html > /dev/null 2>&1
	docker exec php74 chown -R www-data:www-data /var/www/html > /dev/null 2>&1
	cd /home/web && docker compose restart nginx php php74
}

# 升级 nginx
nginx_upgrade() {
	local ldnmp_pods="nginx"
	cd /home/web/
	docker rm -f $ldnmp_pods > /dev/null 2>&1
	docker images --filter=reference="kjlion/${ldnmp_pods}*" -q | xargs docker rmi > /dev/null 2>&1
	docker images --filter=reference="${ldnmp_pods}*" -q | xargs docker rmi > /dev/null 2>&1
	docker compose up -d --force-recreate $ldnmp_pods
	crontab -l 2>/dev/null | grep -v 'logrotate' | crontab -
	(crontab -l 2>/dev/null; echo '0 2 * * * docker exec nginx apk add logrotate && docker exec nginx logrotate -f /etc/logrotate.conf') | crontab -
	docker exec nginx chown -R nginx:nginx /var/www/html
	docker exec nginx mkdir -p /var/cache/nginx/proxy
	docker exec nginx mkdir -p /var/cache/nginx/fastcgi
	docker exec nginx chown -R nginx:nginx /var/cache/nginx/proxy
	docker exec nginx chown -R nginx:nginx /var/cache/nginx/fastcgi
	docker restart $ldnmp_pods > /dev/null 2>&1

	# "更新$ldnmp_pods"
	echo "更新${ldnmp_pods}完成"
}

# 升级 phpMyAdmin
phpmyadmin_upgrade() {
	local ldnmp_pods="phpmyadmin"
	local docker_port=8877
	local dbuse=$(grep -oP 'MYSQL_USER:\s*\K.*' /home/web/docker-compose.yml | tr -d '[:space:]')
	local dbusepasswd=$(grep -oP 'MYSQL_PASSWORD:\s*\K.*' /home/web/docker-compose.yml | tr -d '[:space:]')

	cd /home/web/
	docker rm -f $ldnmp_pods > /dev/null 2>&1
	docker images --filter=reference="$ldnmp_pods*" -q | xargs docker rmi > /dev/null 2>&1
	curl -sS -O https://raw.githubusercontent.com/kejilion/docker/refs/heads/main/docker-compose.phpmyadmin.yml
	docker compose -f docker-compose.phpmyadmin.yml up -d
	clear
	ip_address

	check_docker_app_ip
	echo "登录信息: "
	echo "用户名: $dbuse"
	echo "密码: $dbusepasswd"
	echo
	# "启动$ldnmp_pods"
}

# 清理 Cloudflare 缓存
cf_purge_cache() {
	local CONFIG_FILE="/home/web/config/cf-purge-cache.txt"
	local API_TOKEN
	local EMAIL
	local ZONE_IDS

	# 检查配置文件是否存在
	if [ -f "$CONFIG_FILE" ]; then
	# 从配置文件读取 API_TOKEN 和 zone_id
	read API_TOKEN EMAIL ZONE_IDS < "$CONFIG_FILE"
	# 将 ZONE_IDS 转换为数组
	ZONE_IDS=($ZONE_IDS)
	else
	# 提示用户是否清理缓存
	read -e -p "需要清理 Cloudflare 的缓存吗？（y/n）: " answer
	if [[ "$answer" == "y" ]]; then
		echo "CF信息保存在$CONFIG_FILE, 可以后期修改CF信息"
		read -e -p "请输入你的 API_TOKEN: " API_TOKEN
		read -e -p "请输入你的CF用户名: " EMAIL
		read -e -p "请输入 zone_id（多个用空格分隔）: " -a ZONE_IDS

		mkdir -p /home/web/config/
		echo "$API_TOKEN $EMAIL ${ZONE_IDS[*]}" > "$CONFIG_FILE"
	fi
	fi

	# 循环遍历每个 zone_id 并执行清除缓存命令
	for ZONE_ID in "${ZONE_IDS[@]}"; do
	echo "正在清除缓存 for zone_id: $ZONE_ID"
	curl -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/purge_cache" \
	-H "X-Auth-Email: $EMAIL" \
	-H "X-Auth-Key: $API_TOKEN" \
	-H "Content-Type: application/json" \
	--data '{"purge_everything":true}'
	done

	echo "缓存清除请求已发送完毕."
}


# 清理站点缓存
web_cache() {
	# "清理站点缓存"
	cf_purge_cache
	cd /home/web && docker compose restart
	restart_redis
}


# 删除站点数据
web_del() {
	# "删除站点数据"
	yuming_list="${1:-}"
	if [ -z "$yuming_list" ]; then
		read -e -p "删除站点数据, 请输入你的域名（多个域名用空格隔开）: " yuming_list
		if [[ -z "$yuming_list" ]]; then
			return
		fi
	fi

	for yuming in $yuming_list; do
		echo "正在删除域名: $yuming"
		rm -r /home/web/html/$yuming > /dev/null 2>&1
		rm /home/web/conf.d/$yuming.conf > /dev/null 2>&1
		rm /home/web/certs/${yuming}_key.pem > /dev/null 2>&1
		rm /home/web/certs/${yuming}_cert.pem > /dev/null 2>&1

		# 将域名转换为数据库名
		dbname=$(echo "$yuming" | sed -e 's/[^A-Za-z0-9]/_/g')
		dbrootpasswd=$(grep -oP 'MYSQL_ROOT_PASSWORD:\s*\K.*' /home/web/docker-compose.yml | tr -d '[:space:]')

		# 删除数据库前检查是否存在, 避免报错
		echo "正在删除数据库: $dbname"
		docker exec mysql mysql -u root -p"$dbrootpasswd" -e "DROP DATABASE ${dbname};" > /dev/null 2>&1
	done

	docker exec nginx nginx -s reload
}

# 开启WAF
nginx_waf() {
	local mode=$1
	if ! grep -q "kjlion/nginx:alpine" /home/web/docker-compose.yml; then
		wget -O /home/web/nginx.conf "${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/nginx10.conf"
	fi

	# 根据 mode 参数来决定开启或关闭 WAF
	if [ "$mode" == "on" ]; then
		# 开启 WAF：去掉注释
		sed -i 's|# load_module /etc/nginx/modules/ngx_http_modsecurity_module.so;|load_module /etc/nginx/modules/ngx_http_modsecurity_module.so;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)# modsecurity on;|\1modsecurity on;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)# modsecurity_rules_file /etc/nginx/modsec/modsecurity.conf;|\1modsecurity_rules_file /etc/nginx/modsec/modsecurity.conf;|' /home/web/nginx.conf > /dev/null 2>&1
	elif [ "$mode" == "off" ]; then
		# 关闭 WAF：加上注释
		sed -i 's|^load_module /etc/nginx/modules/ngx_http_modsecurity_module.so;|# load_module /etc/nginx/modules/ngx_http_modsecurity_module.so;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)modsecurity on;|\1# modsecurity on;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)modsecurity_rules_file /etc/nginx/modsec/modsecurity.conf;|\1# modsecurity_rules_file /etc/nginx/modsec/modsecurity.conf;|' /home/web/nginx.conf > /dev/null 2>&1
	else
		echo "无效的参数：使用 'on' 或 'off'"
		return 1
	fi

	# 检查 nginx 镜像并根据情况处理
	if grep -q "kjlion/nginx:alpine" /home/web/docker-compose.yml; then
		docker exec nginx nginx -s reload
	else
		sed -i 's|nginx:alpine|kjlion/nginx:alpine|g' /home/web/docker-compose.yml
		nginx_upgrade
	fi
}

# 检查WAF状态
check_waf_status() {
	if grep -q "^\s*#\s*modsecurity on;" /home/web/nginx.conf; then
		waf_status=""
	elif grep -q "modsecurity on;" /home/web/nginx.conf; then
		waf_status=" WAF已开启"
	else
		waf_status=""
	fi
}

# 检查CF模式
check_cf_mode() {
	if [ -f "/path/to/fail2ban/config/fail2ban/action.d/cloudflare-docker.conf" ]; then
		CFmessage=" cf模式已开启"
	else
		CFmessage=""
	fi
}

# 开启HTTP
nginx_http_on() {
	local ipv4_pattern='^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
	local ipv6_pattern='^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?))|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?))|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?))|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|(2[0-4][0-9]|[01]?[0-9][0-9]?))))$'
	if [[ ($yuming =~ $ipv4_pattern || $yuming =~ $ipv6_pattern) ]]; then
		sed -i '/if (\$scheme = http) {/,/}/s/^/#/' /home/web/conf.d/${yuming}.conf
	fi
}

# WP_MEMORY_LIMIT
patch_wp_memory_limit() {
	local MEMORY_LIMIT="${1:-256M}"      # 第一个参数, 默认256M
	local MAX_MEMORY_LIMIT="${2:-256M}"  # 第二个参数, 默认256M
	local TARGET_DIR="/home/web/html"    # 路径写死

	find "$TARGET_DIR" -type f -name "wp-config.php" | while read -r FILE; do
	# 删除旧定义
	sed -i "/define(['\"]WP_MEMORY_LIMIT['\"].*/d" "$FILE"
	sed -i "/define(['\"]WP_MAX_MEMORY_LIMIT['\"].*/d" "$FILE"

	# 插入新定义, 放在含 "Happy publishing" 的行前
	awk -v insert="define('WP_MEMORY_LIMIT', '$MEMORY_LIMIT');\ndefine('WP_MAX_MEMORY_LIMIT', '$MAX_MEMORY_LIMIT');" \
	'
		/Happy publishing/ {
		print insert
		}
		{ print }
	' "$FILE" > "$FILE.tmp" && mv -f "$FILE.tmp" "$FILE"

	echo "[+] Replaced WP_MEMORY_LIMIT in $FILE"
	done
}

# WP_DEBUG
patch_wp_debug() {
	local DEBUG="${1:-false}"           # 第一个参数, 默认false
	local DEBUG_DISPLAY="${2:-false}"   # 第二个参数, 默认false
	local DEBUG_LOG="${3:-false}"       # 第三个参数, 默认false
	local TARGET_DIR="/home/web/html"   # 路径写死

	find "$TARGET_DIR" -type f -name "wp-config.php" | while read -r FILE; do
	# 删除旧定义
	sed -i "/define(['\"]WP_DEBUG['\"].*/d" "$FILE"
	sed -i "/define(['\"]WP_DEBUG_DISPLAY['\"].*/d" "$FILE"
	sed -i "/define(['\"]WP_DEBUG_LOG['\"].*/d" "$FILE"

	# 插入新定义, 放在含 "Happy publishing" 的行前
	awk -v insert="define('WP_DEBUG_DISPLAY', $DEBUG_DISPLAY);\ndefine('WP_DEBUG_LOG', $DEBUG_LOG);" \
	'
		/Happy publishing/ {
		print insert
		}
		{ print }
	' "$FILE" > "$FILE.tmp" && mv -f "$FILE.tmp" "$FILE"

	echo "[+] Replaced WP_DEBUG settings in $FILE"
	done
}

# Brotli压缩
nginx_br() {
	local mode=$1

	if ! grep -q "kjlion/nginx:alpine" /home/web/docker-compose.yml; then
		wget -O /home/web/nginx.conf "${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/nginx10.conf"
	fi

	if [ "$mode" == "on" ]; then
		# 开启 Brotli：去掉注释
		sed -i 's|# load_module /etc/nginx/modules/ngx_http_brotli_filter_module.so;|load_module /etc/nginx/modules/ngx_http_brotli_filter_module.so;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|# load_module /etc/nginx/modules/ngx_http_brotli_static_module.so;|load_module /etc/nginx/modules/ngx_http_brotli_static_module.so;|' /home/web/nginx.conf > /dev/null 2>&1

		sed -i 's|^\(\s*\)# brotli on;|\1brotli on;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)# brotli_static on;|\1brotli_static on;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)# brotli_comp_level \(.*\);|\1brotli_comp_level \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)# brotli_buffers \(.*\);|\1brotli_buffers \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)# brotli_min_length \(.*\);|\1brotli_min_length \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)# brotli_window \(.*\);|\1brotli_window \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)# brotli_types \(.*\);|\1brotli_types \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i '/brotli_types/,+6 s/^\(\s*\)#\s*/\1/' /home/web/nginx.conf

	elif [ "$mode" == "off" ]; then
		# 关闭 Brotli：加上注释
		sed -i 's|^load_module /etc/nginx/modules/ngx_http_brotli_filter_module.so;|# load_module /etc/nginx/modules/ngx_http_brotli_filter_module.so;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^load_module /etc/nginx/modules/ngx_http_brotli_static_module.so;|# load_module /etc/nginx/modules/ngx_http_brotli_static_module.so;|' /home/web/nginx.conf > /dev/null 2>&1

		sed -i 's|^\(\s*\)brotli on;|\1# brotli on;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)brotli_static on;|\1# brotli_static on;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)brotli_comp_level \(.*\);|\1# brotli_comp_level \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)brotli_buffers \(.*\);|\1# brotli_buffers \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)brotli_min_length \(.*\);|\1# brotli_min_length \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)brotli_window \(.*\);|\1# brotli_window \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)brotli_types \(.*\);|\1# brotli_types \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i '/brotli_types/,+6 {
			/^[[:space:]]*[^#[:space:]]/ s/^\(\s*\)/\1# /
		}' /home/web/nginx.conf

	else
		echo "无效的参数：使用 'on' 或 'off'"
		return 1
	fi

	# 检查 nginx 镜像并根据情况处理
	if grep -q "kjlion/nginx:alpine" /home/web/docker-compose.yml; then
		docker exec nginx nginx -s reload
	else
		sed -i 's|nginx:alpine|kjlion/nginx:alpine|g' /home/web/docker-compose.yml
		nginx_upgrade
	fi
}

# Zstd压缩
nginx_zstd() {
	local mode=$1
	if ! grep -q "kjlion/nginx:alpine" /home/web/docker-compose.yml; then
		wget -O /home/web/nginx.conf "${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/nginx10.conf"
	fi

	if [ "$mode" == "on" ]; then
		# 开启 Zstd：去掉注释
		sed -i 's|# load_module /etc/nginx/modules/ngx_http_zstd_filter_module.so;|load_module /etc/nginx/modules/ngx_http_zstd_filter_module.so;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|# load_module /etc/nginx/modules/ngx_http_zstd_static_module.so;|load_module /etc/nginx/modules/ngx_http_zstd_static_module.so;|' /home/web/nginx.conf > /dev/null 2>&1

		sed -i 's|^\(\s*\)# zstd on;|\1zstd on;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)# zstd_static on;|\1zstd_static on;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)# zstd_comp_level \(.*\);|\1zstd_comp_level \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)# zstd_buffers \(.*\);|\1zstd_buffers \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)# zstd_min_length \(.*\);|\1zstd_min_length \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)# zstd_types \(.*\);|\1zstd_types \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i '/zstd_types/,+6 s/^\(\s*\)#\s*/\1/' /home/web/nginx.conf

	elif [ "$mode" == "off" ]; then
		# 关闭 Zstd：加上注释
		sed -i 's|^load_module /etc/nginx/modules/ngx_http_zstd_filter_module.so;|# load_module /etc/nginx/modules/ngx_http_zstd_filter_module.so;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^load_module /etc/nginx/modules/ngx_http_zstd_static_module.so;|# load_module /etc/nginx/modules/ngx_http_zstd_static_module.so;|' /home/web/nginx.conf > /dev/null 2>&1

		sed -i 's|^\(\s*\)zstd on;|\1# zstd on;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)zstd_static on;|\1# zstd_static on;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)zstd_comp_level \(.*\);|\1# zstd_comp_level \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)zstd_buffers \(.*\);|\1# zstd_buffers \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)zstd_min_length \(.*\);|\1# zstd_min_length \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i 's|^\(\s*\)zstd_types \(.*\);|\1# zstd_types \2;|' /home/web/nginx.conf > /dev/null 2>&1
		sed -i '/zstd_types/,+6 {
			/^[[:space:]]*[^#[:space:]]/ s/^\(\s*\)/\1# /
		}' /home/web/nginx.conf

	else
		echo "无效的参数：使用 'on' 或 'off'"
		return 1
	fi

	# 检查 nginx 镜像并根据情况处理
	if grep -q "kjlion/nginx:alpine" /home/web/docker-compose.yml; then
		docker exec nginx nginx -s reload
	else
		sed -i 's|nginx:alpine|kjlion/nginx:alpine|g' /home/web/docker-compose.yml
		nginx_upgrade
	fi
}

# Gzip压缩
nginx_gzip() {
	local mode=$1
	if [ "$mode" == "on" ]; then
		sed -i 's|^\(\s*\)# gzip on;|\1gzip on;|' /home/web/nginx.conf > /dev/null 2>&1
	elif [ "$mode" == "off" ]; then
		sed -i 's|^\(\s*\)gzip on;|\1# gzip on;|' /home/web/nginx.conf > /dev/null 2>&1
	else
		echo "无效的参数：使用 'on' 或 'off'"
		return 1
	fi

	docker exec nginx nginx -s reload
}

# Fail2Ban状态
f2b_status() {
	docker exec -it fail2ban fail2ban-client reload
	sleep 3
	docker exec -it fail2ban fail2ban-client status
}

f2b_status_xxx() {
	docker exec -it fail2ban fail2ban-client status $xxx
}

# SSHD安装
f2b_install_sshd() {

	docker run -d \
		--name=fail2ban \
		--net=host \
		--cap-add=NET_ADMIN \
		--cap-add=NET_RAW \
		-e PUID=1000 \
		-e PGID=1000 \
		-e TZ=Etc/UTC \
		-e VERBOSITY=-vv \
		-v /path/to/fail2ban/config:/config \
		-v /var/log:/var/log:ro \
		-v /home/web/log/nginx/:/remotelogs/nginx:ro \
		--restart unless-stopped \
		lscr.io/linuxserver/fail2ban:latest

	sleep 3
	if grep -q 'Alpine' /etc/issue; then
		cd /path/to/fail2ban/config/fail2ban/filter.d
		curl -sS -O ${gh_proxy}raw.githubusercontent.com/kejilion/config/main/fail2ban/alpine-sshd.conf
		curl -sS -O ${gh_proxy}raw.githubusercontent.com/kejilion/config/main/fail2ban/alpine-sshd-ddos.conf
		cd /path/to/fail2ban/config/fail2ban/jail.d/
		curl -sS -O ${gh_proxy}raw.githubusercontent.com/kejilion/config/main/fail2ban/alpine-ssh.conf
	elif command -v dnf &>/dev/null; then
		cd /path/to/fail2ban/config/fail2ban/jail.d/
		curl -sS -O ${gh_proxy}raw.githubusercontent.com/kejilion/config/main/fail2ban/centos-ssh.conf
	else
		install rsyslog
		systemctl start rsyslog
		systemctl enable rsyslog
		cd /path/to/fail2ban/config/fail2ban/jail.d/
		curl -sS -O ${gh_proxy}raw.githubusercontent.com/kejilion/config/main/fail2ban/linux-ssh.conf
		systemctl restart rsyslog
	fi

	rm -f /path/to/fail2ban/config/fail2ban/jail.d/sshd.conf
}

# SSHD状态
f2b_sshd() {
	if grep -q 'Alpine' /etc/issue; then
		xxx=alpine-sshd
		f2b_status_xxx
	else
		xxx=sshd
		f2b_status_xxx
	fi
}

# 网络安全
web_security() {
	# "LDNMP环境防御"
	while true; do
	check_waf_status
	check_cf_mode
	if [ -x "$(command -v fail2ban-client)" ] ; then
		clear
		remove fail2ban
		rm -rf /etc/fail2ban
	else
			clear
			rm -f /path/to/fail2ban/config/fail2ban/jail.d/sshd.conf > /dev/null 2>&1
			docker exec -it fail2ban fail2ban-client reload > /dev/null 2>&1
			docker_name="fail2ban"
			check_docker_app
			echo -e "服务器网站防御程序 ${check_docker}${green}${CFmessage}${waf_status}${white}"
			echo "------------------------"
			echo "1. 安装防御程序"
			echo "------------------------"
			echo "5. 查看SSH拦截记录                6. 查看网站拦截记录"
			echo "7. 查看防御规则列表               8. 查看日志实时监控"
			echo "------------------------"
			echo "11. 配置拦截参数                  12. 清除所有拉黑的IP"
			echo "------------------------"
			echo "21. cloudflare模式                22. 高负载开启5秒盾"
			echo "------------------------"
			echo "31. 开启WAF                       32. 关闭WAF"
			echo "33. 开启DDOS防御                  34. 关闭DDOS防御"
			echo "------------------------"
			echo "9. 卸载防御程序"
			echo "------------------------"
			echo -e "${yellow}0.     ${white}返回上一级菜单"
			echo "------------------------"
			read -e -p "请输入你的选择: " sub_choice
			case $sub_choice in
				1)
					f2b_install_sshd
					cd /path/to/fail2ban/config/fail2ban/filter.d
					curl -sS -O ${gh_proxy}raw.githubusercontent.com/kejilion/sh/main/fail2ban-nginx-cc.conf
					cd /path/to/fail2ban/config/fail2ban/jail.d/
					curl -sS -O ${gh_proxy}raw.githubusercontent.com/kejilion/config/main/fail2ban/nginx-docker-cc.conf
					sed -i "/cloudflare/d" /path/to/fail2ban/config/fail2ban/jail.d/nginx-docker-cc.conf
					f2b_status
					;;
				5)
					echo "------------------------"
					f2b_sshd
					echo "------------------------"
					;;
				6)

					echo "------------------------"
					local xxx="fail2ban-nginx-cc"
					f2b_status_xxx
					echo "------------------------"
					local xxx="docker-nginx-418"
					f2b_status_xxx
					echo "------------------------"
					local xxx="docker-nginx-bad-request"
					f2b_status_xxx
					echo "------------------------"
					local xxx="docker-nginx-badbots"
					f2b_status_xxx
					echo "------------------------"
					local xxx="docker-nginx-botsearch"
					f2b_status_xxx
					echo "------------------------"
					local xxx="docker-nginx-deny"
					f2b_status_xxx
					echo "------------------------"
					local xxx="docker-nginx-http-auth"
					f2b_status_xxx
					echo "------------------------"
					local xxx="docker-nginx-unauthorized"
					f2b_status_xxx
					echo "------------------------"
					local xxx="docker-php-url-fopen"
					f2b_status_xxx
					echo "------------------------"

					;;

				7)
					docker exec -it fail2ban fail2ban-client status
					;;
				8)
					tail -f /path/to/fail2ban/config/log/fail2ban/fail2ban.log

					;;
				9)
					docker rm -f fail2ban
					rm -rf /path/to/fail2ban
					crontab -l | grep -v "CF-Under-Attack.sh" | crontab - 2>/dev/null
					echo "Fail2Ban防御程序已卸载"
					;;

				11)
					install nano
					nano /path/to/fail2ban/config/fail2ban/jail.d/nginx-docker-cc.conf
					f2b_status
					break
					;;

				12)
					docker exec -it fail2ban fail2ban-client unban --all
					;;

				21)
					# "cloudflare模式"
					echo "到cf后台右上角我的个人资料, 选择左侧API令牌, 获取Global API Key"
					echo "https://dash.cloudflare.com/login"
					read -e -p "输入CF的账号: " cfuser
					read -e -p "输入CF的Global API Key: " cftoken

					wget -O /home/web/conf.d/default.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/default11.conf
					docker exec nginx nginx -s reload

					cd /path/to/fail2ban/config/fail2ban/jail.d/
					curl -sS -O ${gh_proxy}raw.githubusercontent.com/kejilion/config/main/fail2ban/nginx-docker-cc.conf

					cd /path/to/fail2ban/config/fail2ban/action.d
					curl -sS -O ${gh_proxy}raw.githubusercontent.com/kejilion/config/main/fail2ban/cloudflare-docker.conf

					sed -i "s/kejilion@outlook.com/$cfuser/g" /path/to/fail2ban/config/fail2ban/action.d/cloudflare-docker.conf
					sed -i "s/APIKEY00000/$cftoken/g" /path/to/fail2ban/config/fail2ban/action.d/cloudflare-docker.conf
					f2b_status

					echo "已配置cloudflare模式, 可在cf后台, 站点-安全性-事件中查看拦截记录"
					;;

				22)
					# "高负载开启5秒盾"
					echo -e "${yellow}网站每5分钟自动检测, 当达检测到高负载会自动开盾, 低负载也会自动关闭5秒盾.${white}"
					echo "--------------"
					echo "获取CF参数: "
					echo -e "到cf后台右上角我的个人资料, 选择左侧API令牌, 获取${yellow}Global API Key${white}"
					echo -e "到cf后台域名概要页面右下方获取${yellow}区域ID${white}"
					echo "https://dash.cloudflare.com/login"
					echo "--------------"
					read -e -p "输入CF的账号: " cfuser
					read -e -p "输入CF的Global API Key: " cftoken
					read -e -p "输入CF中域名的区域ID: " cfzonID

					cd ~
					install jq bc
					check_crontab_installed
					curl -sS -O ${gh_proxy}raw.githubusercontent.com/kejilion/sh/main/CF-Under-Attack.sh
					chmod +x CF-Under-Attack.sh
					sed -i "s/AAAA/$cfuser/g" ~/CF-Under-Attack.sh
					sed -i "s/BBBB/$cftoken/g" ~/CF-Under-Attack.sh
					sed -i "s/CCCC/$cfzonID/g" ~/CF-Under-Attack.sh

					local cron_job="*/5 * * * * ~/CF-Under-Attack.sh"

					local existing_cron=$(crontab -l 2>/dev/null | grep -F "$cron_job")

					if [ -z "$existing_cron" ]; then
						(crontab -l 2>/dev/null; echo "$cron_job") | crontab -
						echo "高负载自动开盾脚本已添加"
					else
						echo "自动开盾脚本已存在, 无需添加"
					fi

					;;

				31)
					nginx_waf on
					echo "站点WAF已开启"
					# "站点WAF已开启"
					;;

				32)
					nginx_waf off
					echo "站点WAF已关闭"
					# "站点WAF已关闭"
					;;

				33)
					enable_ddos_defense
					;;

				34)
					disable_ddos_defense
					;;

				*)
					break
					;;
			esac
	fi
	done
}

# 打开iptables
iptables_open() {
	install iptables
	save_iptables_rules
	iptables -P INPUT ACCEPT
	iptables -P FORWARD ACCEPT
	iptables -P OUTPUT ACCEPT
	iptables -F

	ip6tables -P INPUT ACCEPT
	ip6tables -P FORWARD ACCEPT
	ip6tables -P OUTPUT ACCEPT
	ip6tables -F

}


open_port() {
	local ports=($@)  # 将传入的参数转换为数组
	if [ ${#ports[@]} -eq 0 ]; then
		echo "请提供至少一个端口号"
		return 1
	fi

	install iptables

	for port in "${ports[@]}"; do
		# 删除已存在的关闭规则
		iptables -D INPUT -p tcp --dport $port -j DROP 2>/dev/null
		iptables -D INPUT -p udp --dport $port -j DROP 2>/dev/null

		# 添加打开规则
		if ! iptables -C INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null; then
			iptables -I INPUT 1 -p tcp --dport $port -j ACCEPT
		fi

		if ! iptables -C INPUT -p udp --dport $port -j ACCEPT 2>/dev/null; then
			iptables -I INPUT 1 -p udp --dport $port -j ACCEPT
			echo "已打开端口 $port"
		fi
	done

	save_iptables_rules
	# "已打开端口"
}


close_port() {
	local ports=($@)  # 将传入的参数转换为数组
	if [ ${#ports[@]} -eq 0 ]; then
		echo "请提供至少一个端口号"
		return 1
	fi

	install iptables

	for port in "${ports[@]}"; do
		# 删除已存在的打开规则
		iptables -D INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null
		iptables -D INPUT -p udp --dport $port -j ACCEPT 2>/dev/null

		# 添加关闭规则
		if ! iptables -C INPUT -p tcp --dport $port -j DROP 2>/dev/null; then
			iptables -I INPUT 1 -p tcp --dport $port -j DROP
		fi

		if ! iptables -C INPUT -p udp --dport $port -j DROP 2>/dev/null; then
			iptables -I INPUT 1 -p udp --dport $port -j DROP
			echo "已关闭端口 $port"
		fi
	done

	# 删除已存在的规则（如果有）
	iptables -D INPUT -i lo -j ACCEPT 2>/dev/null
	iptables -D FORWARD -i lo -j ACCEPT 2>/dev/null

	# 插入新规则到第一条
	iptables -I INPUT 1 -i lo -j ACCEPT
	iptables -I FORWARD 1 -i lo -j ACCEPT

	save_iptables_rules
	# "已关闭端口"
}


allow_ip() {
	local ips=($@)  # 将传入的参数转换为数组
	if [ ${#ips[@]} -eq 0 ]; then
		echo "请提供至少一个IP地址或IP段"
		return 1
	fi

	install iptables

	for ip in "${ips[@]}"; do
		# 删除已存在的阻止规则
		iptables -D INPUT -s $ip -j DROP 2>/dev/null

		# 添加允许规则
		if ! iptables -C INPUT -s $ip -j ACCEPT 2>/dev/null; then
			iptables -I INPUT 1 -s $ip -j ACCEPT
			echo "已放行IP $ip"
		fi
	done

	save_iptables_rules
	# "已放行IP"
}

block_ip() {
	local ips=($@)  # 将传入的参数转换为数组
	if [ ${#ips[@]} -eq 0 ]; then
		echo "请提供至少一个IP地址或IP段"
		return 1
	fi

	install iptables

	for ip in "${ips[@]}"; do
		# 删除已存在的允许规则
		iptables -D INPUT -s $ip -j ACCEPT 2>/dev/null

		# 添加阻止规则
		if ! iptables -C INPUT -s $ip -j DROP 2>/dev/null; then
			iptables -I INPUT 1 -s $ip -j DROP
			echo "已阻止IP $ip"
		fi
	done

	save_iptables_rules
	# "已阻止IP"
}

# 检查nginx模式
check_nginx_mode() {

	CONFIG_FILE="/home/web/nginx.conf"

	# 获取当前的 worker_processes 设置值
	current_value=$(grep -E '^\s*worker_processes\s+[0-9]+;' "$CONFIG_FILE" | awk '{print $2}' | tr -d ';')

	# 根据值设置模式信息
	if [ "$current_value" = "8" ]; then
		mode_info=" 高性能模式"
	else
		mode_info=" 标准模式"
	fi
}

# 检查nginx压缩设置
check_nginx_compression() {

	CONFIG_FILE="/home/web/nginx.conf"

	# 检查 zstd 是否开启且未被注释（整行以 zstd on; 开头）
	if grep -qE '^\s*zstd\s+on;' "$CONFIG_FILE"; then
		zstd_status=" zstd压缩已开启"
	else
		zstd_status=""
	fi

	# 检查 brotli 是否开启且未被注释
	if grep -qE '^\s*brotli\s+on;' "$CONFIG_FILE"; then
		br_status=" br压缩已开启"
	else
		br_status=""
	fi

	# 检查 gzip 是否开启且未被注释
	if grep -qE '^\s*gzip\s+on;' "$CONFIG_FILE"; then
		gzip_status=" gzip压缩已开启"
	else
		gzip_status=""
	fi
}

# 网站搭建优化函数
optimize_web_server() {
	echo -e "${green}切换到网站搭建优化模式...${white}"

	echo -e "${green}优化文件描述符...${white}"
	ulimit -n 65535

	echo -e "${green}优化虚拟内存...${white}"
	sysctl -w vm.swappiness=10 2>/dev/null
	sysctl -w vm.dirty_ratio=20 2>/dev/null
	sysctl -w vm.dirty_background_ratio=10 2>/dev/null
	sysctl -w vm.overcommit_memory=1 2>/dev/null
	sysctl -w vm.min_free_kbytes=65536 2>/dev/null

	echo -e "${green}优化网络设置...${white}"
	sysctl -w net.core.rmem_max=16777216 2>/dev/null
	sysctl -w net.core.wmem_max=16777216 2>/dev/null
	sysctl -w net.core.netdev_max_backlog=5000 2>/dev/null
	sysctl -w net.core.somaxconn=4096 2>/dev/null
	sysctl -w net.ipv4.tcp_rmem='4096 87380 16777216' 2>/dev/null
	sysctl -w net.ipv4.tcp_wmem='4096 65536 16777216' 2>/dev/null
	sysctl -w net.ipv4.tcp_congestion_control=bbr 2>/dev/null
	sysctl -w net.ipv4.tcp_max_syn_backlog=8192 2>/dev/null
	sysctl -w net.ipv4.tcp_tw_reuse=1 2>/dev/null
	sysctl -w net.ipv4.ip_local_port_range='1024 65535' 2>/dev/null

	echo -e "${green}优化缓存管理...${white}"
	sysctl -w vm.vfs_cache_pressure=50 2>/dev/null

	echo -e "${green}优化CPU设置...${white}"
	sysctl -w kernel.sched_autogroup_enabled=0 2>/dev/null

	echo -e "${green}其他优化...${white}"
	# 禁用透明大页面, 减少延迟
	echo never > /sys/kernel/mm/transparent_hugepage/enabled
	# 禁用 NUMA balancing
	sysctl -w kernel.numa_balancing=0 2>/dev/null
}

# 均衡模式优化函数
optimize_balanced() {
	echo -e "${green}切换到均衡模式...${white}"

	echo -e "${green}优化文件描述符...${white}"
	ulimit -n 32768

	echo -e "${green}优化虚拟内存...${white}"
	sysctl -w vm.swappiness=30 2>/dev/null
	sysctl -w vm.dirty_ratio=20 2>/dev/null
	sysctl -w vm.dirty_background_ratio=10 2>/dev/null
	sysctl -w vm.overcommit_memory=0 2>/dev/null
	sysctl -w vm.min_free_kbytes=32768 2>/dev/null

	echo -e "${green}优化网络设置...${white}"
	sysctl -w net.core.rmem_max=8388608 2>/dev/null
	sysctl -w net.core.wmem_max=8388608 2>/dev/null
	sysctl -w net.core.netdev_max_backlog=125000 2>/dev/null
	sysctl -w net.core.somaxconn=2048 2>/dev/null
	sysctl -w net.ipv4.tcp_rmem='4096 87380 8388608' 2>/dev/null
	sysctl -w net.ipv4.tcp_wmem='4096 32768 8388608' 2>/dev/null
	sysctl -w net.ipv4.tcp_congestion_control=bbr 2>/dev/null
	sysctl -w net.ipv4.tcp_max_syn_backlog=4096 2>/dev/null
	sysctl -w net.ipv4.tcp_tw_reuse=1 2>/dev/null
	sysctl -w net.ipv4.ip_local_port_range='1024 49151' 2>/dev/null

	echo -e "${green}优化缓存管理...${white}"
	sysctl -w vm.vfs_cache_pressure=75 2>/dev/null

	echo -e "${green}优化CPU设置...${white}"
	sysctl -w kernel.sched_autogroup_enabled=1 2>/dev/null

	echo -e "${green}其他优化...${white}"
	# 还原透明大页面
	echo always > /sys/kernel/mm/transparent_hugepage/enabled
	# 还原 NUMA balancing
	sysctl -w kernel.numa_balancing=1 2>/dev/null
}

# 网站优化
web_optimization() {
	while true; do
		check_nginx_mode
		check_nginx_compression
		clear
		# "优化LDNMP环境"
		echo -e "优化LDNMP环境${green}${mode_info}${gzip_status}${br_status}${zstd_status}${white}"
		echo "------------------------"
		echo "1. 标准模式              2. 高性能模式 (推荐2H4G以上)"
		echo "------------------------"
		echo "3. 开启gzip压缩          4. 关闭gzip压缩"
		echo "5. 开启br压缩            6. 关闭br压缩"
		echo "7. 开启zstd压缩          8. 关闭zstd压缩"
		echo "------------------------"
		echo -e "${yellow}0.     ${white}返回上一级菜单"
		echo "------------------------"
		read -e -p "请输入你的选择: " sub_choice
		case $sub_choice in
			1)
			# "站点标准模式"

			# nginx调优
			sed -i 's/worker_connections.*/worker_connections 10240;/' /home/web/nginx.conf
			sed -i 's/worker_processes.*/worker_processes 4;/' /home/web/nginx.conf

			# php调优
			wget -O /home/optimized_php.ini ${gh_proxy}raw.githubusercontent.com/kejilion/sh/main/optimized_php.ini
			docker cp /home/optimized_php.ini php:/usr/local/etc/php/conf.d/optimized_php.ini
			docker cp /home/optimized_php.ini php74:/usr/local/etc/php/conf.d/optimized_php.ini
			rm -rf /home/optimized_php.ini

			# php调优
			wget -O /home/www.conf ${gh_proxy}raw.githubusercontent.com/kejilion/sh/main/www-1.conf
			docker cp /home/www.conf php:/usr/local/etc/php-fpm.d/www.conf
			docker cp /home/www.conf php74:/usr/local/etc/php-fpm.d/www.conf
			rm -rf /home/www.conf

			patch_wp_memory_limit
			patch_wp_debug

			fix_phpfpm_conf php
			fix_phpfpm_conf php74

			# mysql调优
			wget -O /home/custom_mysql_config.cnf ${gh_proxy}raw.githubusercontent.com/kejilion/sh/main/custom_mysql_config-1.cnf
			docker cp /home/custom_mysql_config.cnf mysql:/etc/mysql/conf.d/
			rm -rf /home/custom_mysql_config.cnf


			cd /home/web && docker compose restart

			restart_redis
			optimize_balanced


			echo "LDNMP环境已设置成 标准模式"

				;;
			2)
			# "站点高性能模式"

			# nginx调优
			sed -i 's/worker_connections.*/worker_connections 20480;/' /home/web/nginx.conf
			sed -i 's/worker_processes.*/worker_processes 8;/' /home/web/nginx.conf

			# php调优
			wget -O /home/optimized_php.ini ${gh_proxy}raw.githubusercontent.com/kejilion/sh/main/optimized_php.ini
			docker cp /home/optimized_php.ini php:/usr/local/etc/php/conf.d/optimized_php.ini
			docker cp /home/optimized_php.ini php74:/usr/local/etc/php/conf.d/optimized_php.ini
			rm -rf /home/optimized_php.ini

			# php调优
			wget -O /home/www.conf ${gh_proxy}raw.githubusercontent.com/kejilion/sh/main/www.conf
			docker cp /home/www.conf php:/usr/local/etc/php-fpm.d/www.conf
			docker cp /home/www.conf php74:/usr/local/etc/php-fpm.d/www.conf
			rm -rf /home/www.conf

			patch_wp_memory_limit 512M 512M
			patch_wp_debug

			fix_phpfpm_conf php
			fix_phpfpm_conf php74

			# mysql调优
			wget -O /home/custom_mysql_config.cnf ${gh_proxy}raw.githubusercontent.com/kejilion/sh/main/custom_mysql_config.cnf
			docker cp /home/custom_mysql_config.cnf mysql:/etc/mysql/conf.d/
			rm -rf /home/custom_mysql_config.cnf

			cd /home/web && docker compose restart

			restart_redis
			optimize_web_server

			echo "LDNMP环境已设置成 高性能模式"

				;;
			3)
			# "nginx_gzip on"
			nginx_gzip on
				;;
			4)
			# "nginx_gzip off"
			nginx_gzip off
				;;
			5)
			# "nginx_br on"
			nginx_br on
				;;
			6)
			# "nginx_br off"
			nginx_br off
				;;
			7)
			# "nginx_zstd on"
			nginx_zstd on
				;;
			8)
			# "nginx_zstd off"
			nginx_zstd off
				;;
			*)
				break
				;;
		esac
		break_end
	done
}

# 网页状态
ldnmp_web_status() {
	root_use
	while true; do
		local cert_count=$(ls /home/web/certs/*_cert.pem 2>/dev/null | wc -l)
		local output="${green}${cert_count}${white}"

		local dbrootpasswd=$(grep -oP 'MYSQL_ROOT_PASSWORD:\s*\K.*' /home/web/docker-compose.yml | tr -d '[:space:]')
		local db_count=$(docker exec mysql mysql -u root -p"$dbrootpasswd" -e "SHOW DATABASES;" 2> /dev/null | grep -Ev "Database|information_schema|mysql|performance_schema|sys" | wc -l)
		local db_output="${green}${db_count}${white}"

		clear
		#  "LDNMP站点管理"
		echo "LDNMP环境"
		echo "------------------------"
		ldnmp_v

		echo -e "站点: ${output}                      证书到期时间"
		echo -e "------------------------"
		for cert_file in /home/web/certs/*_cert.pem; do
			local domain=$(basename "$cert_file" | sed 's/_cert.pem//')
			if [ -n "$domain" ]; then
			local expire_date=$(openssl x509 -noout -enddate -in "$cert_file" | awk -F'=' '{print $2}')
			local formatted_date=$(date -d "$expire_date" '+%Y-%m-%d')
			printf "%-30s%s\n" "$domain" "$formatted_date"
			fi
		done

		echo "------------------------"
		echo ""
		echo -e "数据库: ${db_output}"
		echo -e "------------------------"
		local dbrootpasswd=$(grep -oP 'MYSQL_ROOT_PASSWORD:\s*\K.*' /home/web/docker-compose.yml | tr -d '[:space:]')
		docker exec mysql mysql -u root -p"$dbrootpasswd" -e "SHOW DATABASES;" 2> /dev/null | grep -Ev "Database|information_schema|mysql|performance_schema|sys"

		echo "------------------------"
		echo ""
		echo "站点目录"
		echo "------------------------"
		echo -e "数据 ${grey}/home/web/html${white}     证书 ${grey}/home/web/certs${white}     配置 ${grey}/home/web/conf.d${white}"
		echo "------------------------"
		echo ""
		echo "操作"
		echo "------------------------"
		echo "1.  申请/更新域名证书               2.  更换站点域名"
		echo "3.  清理站点缓存                    4.  创建关联站点"
		echo "5.  查看访问日志                    6.  查看错误日志"
		echo "7.  编辑全局配置                    8.  编辑站点配置"
		echo "9.  管理站点数据库		    10. 查看站点分析报告"
		echo "------------------------"
		echo "20. 删除指定站点数据"
		echo "------------------------"
		echo -e "${yellow}0.     ${white}返回上一级菜单"
		echo "------------------------"
		read -e -p "请输入你的选择: " sub_choice
		case $sub_choice in
			1)
				#  "申请域名证书"
				read -e -p "请输入你的域名: " yuming
				install_certbot
				docker run -it --rm -v /etc/letsencrypt/:/etc/letsencrypt certbot/certbot delete --cert-name "$yuming" -n 2>/dev/null
				install_ssltls
				certs_status

				;;

			2)
				#  "更换站点域名"
				echo -e "${red}强烈建议: ${white}先备份好全站数据再更换站点域名!"
				read -e -p "请输入旧域名: " oddyuming
				read -e -p "请输入新域名: " yuming
				install_certbot
				install_ssltls
				certs_status

				# mysql替换
				add_db

				local odd_dbname=$(echo "$oddyuming" | sed -e 's/[^A-Za-z0-9]/_/g')
				local odd_dbname="${odd_dbname}"

				docker exec mysql mysqldump -u root -p"$dbrootpasswd" $odd_dbname | docker exec -i mysql mysql -u root -p"$dbrootpasswd" $dbname
				docker exec mysql mysql -u root -p"$dbrootpasswd" -e "DROP DATABASE $odd_dbname;"


				local tables=$(docker exec mysql mysql -u root -p"$dbrootpasswd" -D $dbname -e "SHOW TABLES;" | awk '{ if (NR>1) print $1 }')
				for table in $tables; do
					columns=$(docker exec mysql mysql -u root -p"$dbrootpasswd" -D $dbname -e "SHOW COLUMNS FROM $table;" | awk '{ if (NR>1) print $1 }')
					for column in $columns; do
						docker exec mysql mysql -u root -p"$dbrootpasswd" -D $dbname -e "UPDATE $table SET $column = REPLACE($column, '$oddyuming', '$yuming') WHERE $column LIKE '%$oddyuming%';"
					done
				done

				# 网站目录替换
				mv /home/web/html/$oddyuming /home/web/html/$yuming

				find /home/web/html/$yuming -type f -exec sed -i "s/$odd_dbname/$dbname/g" {} +
				find /home/web/html/$yuming -type f -exec sed -i "s/$oddyuming/$yuming/g" {} +

				mv /home/web/conf.d/$oddyuming.conf /home/web/conf.d/$yuming.conf
				sed -i "s/$oddyuming/$yuming/g" /home/web/conf.d/$yuming.conf

				rm /home/web/certs/${oddyuming}_key.pem
				rm /home/web/certs/${oddyuming}_cert.pem

				docker exec nginx nginx -s reload

				;;


			3)
				web_cache
				;;
			4)
				#  "创建关联站点"
				echo -e "为现有的站点再关联一个新域名用于访问"
				read -e -p "请输入现有的域名: " oddyuming
				read -e -p "请输入新域名: " yuming
				install_certbot
				install_ssltls
				certs_status

				cp /home/web/conf.d/$oddyuming.conf /home/web/conf.d/$yuming.conf
				sed -i "s|server_name $oddyuming|server_name $yuming|g" /home/web/conf.d/$yuming.conf
				sed -i "s|/etc/nginx/certs/${oddyuming}_cert.pem|/etc/nginx/certs/${yuming}_cert.pem|g" /home/web/conf.d/$yuming.conf
				sed -i "s|/etc/nginx/certs/${oddyuming}_key.pem|/etc/nginx/certs/${yuming}_key.pem|g" /home/web/conf.d/$yuming.conf

				docker exec nginx nginx -s reload

				;;
			5)
				#  "查看访问日志"
				tail -n 200 /home/web/log/nginx/access.log
				break_end
				;;
			6)
				#  "查看错误日志"
				tail -n 200 /home/web/log/nginx/error.log
				break_end
				;;
			7)
				#  "编辑全局配置"
				install nano
				nano /home/web/nginx.conf
				docker exec nginx nginx -s reload
				;;

			8)
				#  "编辑站点配置"
				read -e -p "编辑站点配置, 请输入你要编辑的域名: " yuming
				install nano
				nano /home/web/conf.d/$yuming.conf
				docker exec nginx nginx -s reload
				;;
			9)
				phpmyadmin_upgrade
				break_end
				;;
			10)
				#  "查看站点数据"
				install goaccess
				goaccess --log-format=COMBINED /home/web/log/nginx/access.log
				;;

			20)
				web_del
				docker run -it --rm -v /etc/letsencrypt/:/etc/letsencrypt certbot/certbot delete --cert-name "$yuming" -n 2>/dev/null

				;;
			*)
				break  # 跳出循环, 退出菜单
				;;
		esac
	done
}

# 站点信息
ldnmp_tato() {
local cert_count=$(ls /home/web/certs/*_cert.pem 2>/dev/null | wc -l)
local output="${green}${cert_count}${white}"

local dbrootpasswd=$(grep -oP 'MYSQL_ROOT_PASSWORD:\s*\K.*' /home/web/docker-compose.yml 2>/dev/null | tr -d '[:space:]')
if [ -n "$dbrootpasswd" ]; then
	local db_count=$(docker exec mysql mysql -u root -p"$dbrootpasswd" -e "SHOW DATABASES;" 2>/dev/null | grep -Ev "Database|information_schema|mysql|performance_schema|sys" | wc -l)
fi

local db_output="${green}${db_count}${white}"


if command -v docker &>/dev/null; then
	if docker ps --filter "name=nginx" --filter "status=running" | grep -q nginx; then
		echo -e "${green}环境已安装${white}  站点: $output  数据库: $db_output"
		echo -e "${pink}------------------------------------------------------------------------${white}"
	fi
fi

}

# 修复PHP-FPM配置
fix_phpfpm_conf() {
	local container_name=$1
	docker exec "$container_name" sh -c "mkdir -p /run/$container_name && chmod 777 /run/$container_name"
	docker exec "$container_name" sh -c "sed -i '1i [global]\\ndaemonize = no' /usr/local/etc/php-fpm.d/www.conf"
	docker exec "$container_name" sh -c "sed -i '/^listen =/d' /usr/local/etc/php-fpm.d/www.conf"
	docker exec "$container_name" sh -c "echo -e '\nlisten = /run/$container_name/php-fpm.sock\nlisten.owner = www-data\nlisten.group = www-data\nlisten.mode = 0777' >> /usr/local/etc/php-fpm.d/www.conf"
	docker exec "$container_name" sh -c "rm -f /usr/local/etc/php-fpm.d/zz-docker.conf"

	find /home/web/conf.d/ -type f -name "*.conf" -exec sed -i "s#fastcgi_pass ${container_name}:9000;#fastcgi_pass unix:/run/${container_name}/php-fpm.sock;#g" {} \;

}

# 检查LDNMP环境安装状态
ldnmp_install_status_one() {

	if docker inspect "php" &>/dev/null; then
		clear
		# "无法再次安装LDNMP环境"
		echo -e "${yellow}提示: ${white}建站环境已安装.无需再次安装!"
		break_end
		linux_ldnmp
	fi
}

# LDNMP环境安装
ldnmp_install_all() {
	cd ~
	# "安装LDNMP环境"
	root_use
	clear
	echo -e "${yellow}LDNMP环境未安装, 开始安装LDNMP环境...${white}"
	check_disk_space 3
	check_port
	dependency_check
	install_docker
	install_certbot
	install_ldnmp_conf
	install_ldnmp
}

# Nginx环境安装
nginx_install_all() {
	cd ~
	# "安装nginx环境"
	root_use
	clear
	echo -e "${yellow}nginx未安装, 开始安装nginx环境...${white}"
	check_disk_space 1
	check_port
	dependency_check
	install_docker
	install_certbot
	install_ldnmp_conf
	nginx_upgrade
	clear
	local nginx_version=$(docker exec nginx nginx -v 2>&1)
	local nginx_version=$(echo "$nginx_version" | grep -oP "nginx/\K[0-9]+\.[0-9]+\.[0-9]+")
	echo "nginx已安装完成"
	echo -e "当前版本: ${yellow}v$nginx_version${white}"
	echo ""
}

# LDNMP环境检测
ldnmp_install_status() {
	if ! docker inspect "php" &>/dev/null; then
		# "请先安装LDNMP环境"
		ldnmp_install_all
	fi
}

# Nginx环境检测
nginx_install_status() {
	if ! docker inspect "nginx" &>/dev/null; then
		# "请先安装nginx环境"
		nginx_install_all
	fi
}

# 	Web_ON
ldnmp_web_on() {
	clear
	echo "您的 $webname 搭建好了!"
	echo "https://$yuming"
	echo "------------------------"
	echo "$webname 安装信息如下: "
}

# Nginx
nginx_web_on() {
	clear
	echo "您的 $webname 搭建好了!"
	echo "https://$yuming"

}


# WordPress
ldnmp_wp() {
	clear
	# wordpress
	webname="WordPress"
	yuming="${1:-}"
	# "安装$webname"
	echo "开始部署 $webname"
	if [ -z "$yuming" ]; then
		add_yuming
	fi
	repeat_add_yuming
	ldnmp_install_status
	install_ssltls
	certs_status
	add_db
	wget -O /home/web/conf.d/map.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/map.conf
	wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/wordpress.com.conf
	sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
	nginx_http_on

	cd /home/web/html
	mkdir $yuming
	cd $yuming
	wget -O latest.zip ${gh_proxy}github.com/kejilion/Website_source_code/raw/refs/heads/main/wp-latest.zip
	unzip latest.zip
	rm latest.zip
	echo "define('FS_METHOD', 'direct'); define('WP_REDIS_HOST', 'redis'); define('WP_REDIS_PORT', '6379');" >> /home/web/html/$yuming/wordpress/wp-config-sample.php
	sed -i "s|database_name_here|$dbname|g" /home/web/html/$yuming/wordpress/wp-config-sample.php
	sed -i "s|username_here|$dbuse|g" /home/web/html/$yuming/wordpress/wp-config-sample.php
	sed -i "s|password_here|$dbusepasswd|g" /home/web/html/$yuming/wordpress/wp-config-sample.php
	sed -i "s|localhost|mysql|g" /home/web/html/$yuming/wordpress/wp-config-sample.php
	cp /home/web/html/$yuming/wordpress/wp-config-sample.php /home/web/html/$yuming/wordpress/wp-config.php

	restart_ldnmp
	nginx_web_on
}

# 反向代理-IP+端口
ldnmp_Proxy() {
	clear
	webname="反向代理-IP+端口"
	yuming="${1:-}"
	reverseproxy="${2:-}"
	port="${3:-}"

	# "安装$webname"
	echo "开始部署 $webname"
	if [ -z "$yuming" ]; then
		add_yuming
	fi
	if [ -z "$reverseproxy" ]; then
		read -e -p "请输入你的反代IP: " reverseproxy
	fi

	if [ -z "$port" ]; then
		read -e -p "请输入你的反代端口: " port
	fi
	nginx_install_status
	install_ssltls
	certs_status
	wget -O /home/web/conf.d/map.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/map.conf
	wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/reverse-proxy.conf
	sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
	sed -i "s/0.0.0.0/$reverseproxy/g" /home/web/conf.d/$yuming.conf
	sed -i "s|0000|$port|g" /home/web/conf.d/$yuming.conf
	nginx_http_on
	docker exec nginx nginx -s reload
	nginx_web_on
}


# 反向代理-负载均衡
ldnmp_Proxy_backend() {
	clear
	webname="反向代理-负载均衡"
	yuming="${1:-}"
	reverseproxy_port="${2:-}"

	# "安装$webname"
	echo "开始部署 $webname"
	if [ -z "$yuming" ]; then
		add_yuming
	fi

	if [ -z "$reverseproxy_port" ]; then
		read -e -p "请输入你的多个反代IP+端口用空格隔开（例如 127.0.0.1:3000 127.0.0.1:3002）： " reverseproxy_port
	fi

	nginx_install_status
	install_ssltls
	certs_status
	wget -O /home/web/conf.d/map.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/map.conf
	wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/reverse-proxy-backend.conf

	backend=$(tr -dc 'A-Za-z' < /dev/urandom | head -c 8)
	sed -i "s/backend_yuming_com/backend_$backend/g" /home/web/conf.d/"$yuming".conf


	sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf

	upstream_servers=""
	for server in $reverseproxy_port; do
		upstream_servers="$upstream_servers    server $server;\n"
	done

	sed -i "s/# 动态添加/$upstream_servers/g" /home/web/conf.d/$yuming.conf

	nginx_http_on
	docker exec nginx nginx -s reload
	nginx_web_on
}


# 查找容器名称
find_container_by_host_port() {
	port="$1"
	docker_name=$(docker ps --format '{{.ID}} {{.Names}}' | while read id name; do
		if docker port "$id" | grep -q ":$port"; then
			echo "$name"
			break
		fi
	done)
}

# 检查端口
check_port() {
	install lsof

	stop_containers_or_kill_process() {
		local port=$1
		local containers=$(docker ps --filter "publish=$port" --format "{{.ID}}" 2>/dev/null)

		if [ -n "$containers" ]; then
			docker stop $containers
		else
			for pid in $(lsof -t -i:$port); do
				kill -9 $pid
			done
		fi
	}

	stop_containers_or_kill_process 80
	stop_containers_or_kill_process 443
}


# LDNMP环境菜单
linux_ldnmp() {
	while true; do
		clear
		echo -e "${green}===== LDNMP建站菜单 =====${white}"
		echo ""
		ldnmp_tato
		echo -e "${cyan}1.   ${white}安装LDNMP环境 ${yellow}★${white}                   ${yellow}2.   ${white}安装WordPress ${yellow}★${white}"
		echo -e "${cyan}3.   ${white}安装Discuz论坛                    ${cyan}4.   ${white}安装可道云桌面"
		echo -e "${cyan}5.   ${white}安装苹果CMS影视站                 ${cyan}6.   ${white}安装独角数发卡网"
		echo -e "${cyan}7.   ${white}安装flarum论坛网站                ${cyan}8.   ${white}安装typecho轻量博客网站"
		echo -e "${cyan}9.   ${white}安装LinkStack共享链接平台         ${cyan}20.  ${white}自定义动态站点"
		echo -e "${pink}------------------------------------------------------------------------${white}"
		echo -e "${cyan}21.  ${white}仅安装nginx ${yellow}★${white}                     ${cyan}22.  ${white}站点重定向"
		echo -e "${cyan}23.  ${white}站点反向代理-IP+端口 ${yellow}★${white}            ${cyan}24.  ${white}站点反向代理-域名"
		echo -e "${cyan}25.  ${white}安装Bitwarden密码管理平台         ${cyan}26.  ${white}安装Halo博客网站"
		echo -e "${cyan}27.  ${white}安装AI绘画提示词生成器            ${cyan}28.  ${white}站点反向代理-负载均衡"
		echo -e "${cyan}30.  ${white}自定义静态站点"
		echo -e "${pink}------------------------------------------------------------------------${white}"
		echo -e "${cyan}31.  ${white}站点数据管理 ${yellow}★${white}                    ${cyan}32.  ${white}备份全站数据"
		echo -e "${cyan}33.  ${white}定时远程备份                      ${cyan}34.  ${white}还原全站数据"
		echo -e "${pink}------------------------------------------------------------------------${white}"
		echo -e "${cyan}35.  ${white}防护LDNMP环境                     ${cyan}36.  ${white}优化LDNMP环境"
		echo -e "${cyan}37.  ${white}更新LDNMP环境                     ${cyan}38.  ${white}卸载LDNMP环境"
		echo -e "${pink}------------------------------------------------------------------------${white}"
		echo -e "${yellow}0.   ${white}返回主菜单"
		echo -e "${pink}------------------------------------------------------------------------${white}"
		read -e -p "请输入你的选择: " sub_choice

		case $sub_choice in
		1)
		ldnmp_install_status_one
		ldnmp_install_all
			;;
		2)
		ldnmp_wp
			;;

		3)
		clear
		# Discuz论坛
		webname="Discuz论坛"
		#  "安装$webname"
		echo "开始部署 $webname"
		add_yuming
		repeat_add_yuming
		ldnmp_install_status
		install_ssltls
		certs_status
		add_db
		wget -O /home/web/conf.d/map.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/map.conf
		wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/discuz.com.conf
		sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
		nginx_http_on

		cd /home/web/html
		mkdir $yuming
		cd $yuming
		wget -O latest.zip ${gh_proxy}github.com/kejilion/Website_source_code/raw/main/Discuz_X3.5_SC_UTF8_20240520.zip
		unzip latest.zip
		rm latest.zip

		restart_ldnmp

		ldnmp_web_on
		echo "数据库地址: mysql"
		echo "数据库名: $dbname"
		echo "用户名: $dbuse"
		echo "密码: $dbusepasswd"
		echo "表前缀: discuz_"


			;;

		4)
		clear
		# 可道云桌面
		webname="可道云桌面"
		#  "安装$webname"
		echo "开始部署 $webname"
		add_yuming
		repeat_add_yuming
		ldnmp_install_status
		install_ssltls
		certs_status
		add_db
		wget -O /home/web/conf.d/map.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/map.conf
		wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/kdy.com.conf
		sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
		nginx_http_on

		cd /home/web/html
		mkdir $yuming
		cd $yuming
		wget -O latest.zip ${gh_proxy}github.com/kalcaddle/kodbox/archive/refs/tags/1.50.02.zip
		unzip -o latest.zip
		rm latest.zip
		mv /home/web/html/$yuming/kodbox* /home/web/html/$yuming/kodbox
		restart_ldnmp

		ldnmp_web_on
		echo "数据库地址: mysql"
		echo "用户名: $dbuse"
		echo "密码: $dbusepasswd"
		echo "数据库名: $dbname"
		echo "redis主机: redis"

			;;

		5)
		clear
		# 苹果CMS
		webname="苹果CMS"
		#  "安装$webname"
		echo "开始部署 $webname"
		add_yuming
		repeat_add_yuming
		ldnmp_install_status
		install_ssltls
		certs_status
		add_db
		wget -O /home/web/conf.d/map.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/map.conf
		wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/maccms.com.conf
		sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
		nginx_http_on

		cd /home/web/html
		mkdir $yuming
		cd $yuming
		# wget ${gh_proxy}github.com/magicblack/maccms_down/raw/master/maccms10.zip && unzip maccms10.zip && rm maccms10.zip
		wget ${gh_proxy}github.com/magicblack/maccms_down/raw/master/maccms10.zip && unzip maccms10.zip && mv maccms10-*/* . && rm -r maccms10-* && rm maccms10.zip
		cd /home/web/html/$yuming/template/ && wget ${gh_proxy}github.com/kejilion/Website_source_code/raw/main/DYXS2.zip && unzip DYXS2.zip && rm /home/web/html/$yuming/template/DYXS2.zip
		cp /home/web/html/$yuming/template/DYXS2/asset/admin/Dyxs2.php /home/web/html/$yuming/application/admin/controller
		cp /home/web/html/$yuming/template/DYXS2/asset/admin/dycms.html /home/web/html/$yuming/application/admin/view/system
		mv /home/web/html/$yuming/admin.php /home/web/html/$yuming/vip.php && wget -O /home/web/html/$yuming/application/extra/maccms.php ${gh_proxy}raw.githubusercontent.com/kejilion/Website_source_code/main/maccms.php

		restart_ldnmp

		ldnmp_web_on
		echo "数据库地址: mysql"
		echo "数据库端口: 3306"
		echo "数据库名: $dbname"
		echo "用户名: $dbuse"
		echo "密码: $dbusepasswd"
		echo "数据库前缀: mac_"
		echo "------------------------"
		echo "安装成功后登录后台地址"
		echo "https://$yuming/vip.php"

			;;

		6)
		clear
		# 独脚数卡
		webname="独脚数卡"
		#  "安装$webname"
		echo "开始部署 $webname"
		add_yuming
		repeat_add_yuming
		ldnmp_install_status
		install_ssltls
		certs_status
		add_db
		wget -O /home/web/conf.d/map.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/map.conf
		wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/dujiaoka.com.conf
		sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
		nginx_http_on

		cd /home/web/html
		mkdir $yuming
		cd $yuming
		wget ${gh_proxy}github.com/assimon/dujiaoka/releases/download/2.0.6/2.0.6-antibody.tar.gz && tar -zxvf 2.0.6-antibody.tar.gz && rm 2.0.6-antibody.tar.gz

		restart_ldnmp

		ldnmp_web_on
		echo "数据库地址: mysql"
		echo "数据库端口: 3306"
		echo "数据库名: $dbname"
		echo "用户名: $dbuse"
		echo "密码: $dbusepasswd"
		echo ""
		echo "redis地址: redis"
		echo "redis密码: 默认不填写"
		echo "redis端口: 6379"
		echo ""
		echo "网站url: https://$yuming"
		echo "后台登录路径: /admin"
		echo "------------------------"
		echo "用户名: admin"
		echo "密码: admin"
		echo "------------------------"
		echo "登录时右上角如果出现红色error0请使用如下命令: "
		echo "我也很气愤独角数卡为啥这么麻烦, 会有这样的问题!"
		echo "sed -i 's/ADMIN_HTTPS=false/ADMIN_HTTPS=true/g' /home/web/html/$yuming/dujiaoka/.env"

			;;

		7)
		clear
		# flarum论坛
		webname="flarum论坛"
		#  "安装$webname"
		echo "开始部署 $webname"
		add_yuming
		repeat_add_yuming
		ldnmp_install_status
		install_ssltls
		certs_status
		add_db
		wget -O /home/web/conf.d/map.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/map.conf
		wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/flarum.com.conf
		sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
		nginx_http_on

		docker exec php rm -f /usr/local/etc/php/conf.d/optimized_php.ini

		cd /home/web/html
		mkdir $yuming
		cd $yuming

		docker exec php sh -c "php -r \"copy('https://getcomposer.org/installer', 'composer-setup.php');\""
		docker exec php sh -c "php composer-setup.php"
		docker exec php sh -c "php -r \"unlink('composer-setup.php');\""
		docker exec php sh -c "mv composer.phar /usr/local/bin/composer"

		docker exec php composer create-project flarum/flarum /var/www/html/$yuming
		docker exec php sh -c "cd /var/www/html/$yuming && composer require flarum-lang/chinese-simplified"
		docker exec php sh -c "cd /var/www/html/$yuming && composer require flarum/extension-manager:*"
		docker exec php sh -c "cd /var/www/html/$yuming && composer require fof/polls"
		docker exec php sh -c "cd /var/www/html/$yuming && composer require fof/sitemap"
		docker exec php sh -c "cd /var/www/html/$yuming && composer require fof/oauth"
		docker exec php sh -c "cd /var/www/html/$yuming && composer require fof/best-answer:*"
		docker exec php sh -c "cd /var/www/html/$yuming && composer require v17development/flarum-seo"
		docker exec php sh -c "cd /var/www/html/$yuming && composer require clarkwinkelmann/flarum-ext-emojionearea"

		restart_ldnmp


		ldnmp_web_on
		echo "数据库地址: mysql"
		echo "数据库名: $dbname"
		echo "用户名: $dbuse"
		echo "密码: $dbusepasswd"
		echo "表前缀: flarum_"
		echo "管理员信息自行设置"

			;;

		8)
		clear
		# typecho
		webname="typecho"
		#  "安装$webname"
		echo "开始部署 $webname"
		add_yuming
		repeat_add_yuming
		ldnmp_install_status
		install_ssltls
		certs_status
		add_db
		wget -O /home/web/conf.d/map.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/map.conf
		wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/typecho.com.conf
		sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
		nginx_http_on

		cd /home/web/html
		mkdir $yuming
		cd $yuming
		wget -O latest.zip ${gh_proxy}github.com/typecho/typecho/releases/latest/download/typecho.zip
		unzip latest.zip
		rm latest.zip

		restart_ldnmp

		clear
		ldnmp_web_on
		echo "数据库前缀: typecho_"
		echo "数据库地址: mysql"
		echo "用户名: $dbuse"
		echo "密码: $dbusepasswd"
		echo "数据库名: $dbname"

			;;


		9)
		clear
		# LinkStack
		webname="LinkStack"
		#  "安装$webname"
		echo "开始部署 $webname"
		add_yuming
		repeat_add_yuming
		ldnmp_install_status
		install_ssltls
		certs_status
		add_db
		wget -O /home/web/conf.d/map.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/map.conf
		wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/refs/heads/main/index_php.conf
		sed -i "s|/var/www/html/yuming.com/|/var/www/html/yuming.com/linkstack|g" /home/web/conf.d/$yuming.conf
		sed -i "s|yuming.com|$yuming|g" /home/web/conf.d/$yuming.conf
		nginx_http_on

		cd /home/web/html
		mkdir $yuming
		cd $yuming
		wget -O latest.zip ${gh_proxy}github.com/linkstackorg/linkstack/releases/latest/download/linkstack.zip
		unzip latest.zip
		rm latest.zip

		restart_ldnmp

		clear
		ldnmp_web_on
		echo "数据库地址: mysql"
		echo "数据库端口: 3306"
		echo "数据库名: $dbname"
		echo "用户名: $dbuse"
		echo "密码: $dbusepasswd"
			;;

		20)
		clear
		webname="PHP动态站点"
		#  "安装$webname"
		echo "开始部署 $webname"
		add_yuming
		repeat_add_yuming
		ldnmp_install_status
		install_ssltls
		certs_status
		add_db
		wget -O /home/web/conf.d/map.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/map.conf
		wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/index_php.conf
		sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
		nginx_http_on

		cd /home/web/html
		mkdir $yuming
		cd $yuming

		clear
		echo -e "[${yellow}1/6${white}] 上传PHP源码"
		echo "-------------"
		echo "目前只允许上传zip格式的源码包, 请将源码包放到/home/web/html/${yuming}目录下"
		read -e -p "也可以输入下载链接, 远程下载源码包, 直接回车将跳过远程下载： " url_download

		if [ -n "$url_download" ]; then
			wget "$url_download"
		fi

		unzip $(ls -t *.zip | head -n 1)
		rm -f $(ls -t *.zip | head -n 1)

		clear
		echo -e "[${yellow}2/6${white}] index.php所在路径"
		echo "-------------"
		# find "$(realpath .)" -name "index.php" -print
		find "$(realpath .)" -name "index.php" -print | xargs -I {} dirname {}

		read -e -p "请输入index.php的路径, 类似（/home/web/html/$yuming/wordpress/): " index_lujing

		sed -i "s#root /var/www/html/$yuming/#root $index_lujing#g" /home/web/conf.d/$yuming.conf
		sed -i "s#/home/web/#/var/www/#g" /home/web/conf.d/$yuming.conf

		clear
		echo -e "[${yellow}3/6${white}] 请选择PHP版本"
		echo "-------------"
		read -e -p "1. php最新版 | 2. php7.4 : " pho_v
		case "$pho_v" in
			1)
				sed -i "s#php:9000#php:9000#g" /home/web/conf.d/$yuming.conf
				local PHP_Version="php"
				;;
			2)
				sed -i "s#php:9000#php74:9000#g" /home/web/conf.d/$yuming.conf
				local PHP_Version="php74"
				;;
			*)
				echo -e "${red}无效选择, 请重新输入 !${white}"
				sleep 1
				;;
		esac


		clear
		echo -e "[${yellow}4/6${white}] 安装指定扩展"
		echo "-------------"
		echo "已经安装的扩展"
		docker exec php php -m

		read -e -p "$(echo -e "输入需要安装的扩展名称, 如 ${yellow}SourceGuardian imap ftp${white} 等等.直接回车将跳过安装 ： ")" php_extensions
		if [ -n "$php_extensions" ]; then
			docker exec $PHP_Version install-php-extensions $php_extensions
		fi


		clear
		echo -e "[${yellow}5/6${white}] 编辑站点配置"
		echo "-------------"
		echo "按任意键继续, 可以详细设置站点配置, 如伪静态等内容"
		read -n 1 -s -r -p ""
		install nano
		nano /home/web/conf.d/$yuming.conf


		clear
		echo -e "[${yellow}6/6${white}] 数据库管理"
		echo "-------------"
		read -e -p "1. 我搭建新站        2. 我搭建老站有数据库备份： " use_db
		case $use_db in
			1)
				echo
				;;
			2)
				echo "数据库备份必须是.gz结尾的压缩包.请放到/home/目录下, 支持宝塔/1panel备份数据导入."
				read -e -p "也可以输入下载链接, 远程下载备份数据, 直接回车将跳过远程下载： " url_download_db

				cd /home/
				if [ -n "$url_download_db" ]; then
					wget "$url_download_db"
				fi
				gunzip $(ls -t *.gz | head -n 1)
				latest_sql=$(ls -t *.sql | head -n 1)
				dbrootpasswd=$(grep -oP 'MYSQL_ROOT_PASSWORD:\s*\K.*' /home/web/docker-compose.yml | tr -d '[:space:]')
				docker exec -i mysql mysql -u root -p"$dbrootpasswd" $dbname < "/home/$latest_sql"
				echo "数据库导入的表数据"
				docker exec -i mysql mysql -u root -p"$dbrootpasswd" -e "USE $dbname; SHOW TABLES;"
				rm -f *.sql
				echo "数据库导入完成"
				;;
			*)
				echo
				;;
		esac

		docker exec php rm -f /usr/local/etc/php/conf.d/optimized_php.ini

		restart_ldnmp
		ldnmp_web_on
		prefix="web$(shuf -i 10-99 -n 1)_"
		echo "数据库地址: mysql"
		echo "数据库名: $dbname"
		echo "用户名: $dbuse"
		echo "密码: $dbusepasswd"
		echo "表前缀: $prefix"
		echo "管理员登录信息自行设置"

			;;


		21)
		ldnmp_install_status_one
		nginx_install_all
			;;

		22)
		clear
		webname="站点重定向"
		#  "安装$webname"
		echo "开始部署 $webname"
		add_yuming
		read -e -p "请输入跳转域名: " reverseproxy
		nginx_install_status
		install_ssltls
		certs_status

		wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/rewrite.conf
		sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
		sed -i "s/baidu.com/$reverseproxy/g" /home/web/conf.d/$yuming.conf
		nginx_http_on

		docker exec nginx nginx -s reload

		nginx_web_on


			;;

		23)
		ldnmp_Proxy
		find_container_by_host_port "$port"
		if [ -z "$docker_name" ]; then
			# 询问用户是否确认阻止访问
			read -p "是否阻止IP+端口访问该服务？[y/N] " confirm
			# 检查用户输入, 仅当输入y或Y时执行关闭操作
			if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
				close_port "$port"
				echo "已阻止IP+端口访问该服务"
			else
				echo "完成!"
			fi
		else
			ip_address
			block_container_port "$docker_name" "$ipv4_address"
		fi
			;;

		24)
		clear
		webname="反向代理-域名"
		#  "安装$webname"
		echo "开始部署 $webname"
		add_yuming
		echo -e "域名格式: ${yellow}google.com${white}"
		read -e -p "请输入你的反代域名: " fandai_yuming
		nginx_install_status
		install_ssltls
		certs_status

		wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/reverse-proxy-domain.conf
		sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
		sed -i "s|fandaicom|$fandai_yuming|g" /home/web/conf.d/$yuming.conf
		nginx_http_on

		docker exec nginx nginx -s reload

		nginx_web_on

			;;


		25)
		clear
		webname="Bitwarden"
		#  "安装$webname"
		echo "开始部署 $webname"
		add_yuming
		nginx_install_status
		install_ssltls
		certs_status

		docker run -d \
			--name bitwarden \
			--restart always \
			-p 3280:80 \
			-v /home/web/html/$yuming/bitwarden/data:/data \
			vaultwarden/server
		duankou=3280
		reverse_proxy

		nginx_web_on

			;;

		26)
		clear
		webname="halo"
		#  "安装$webname"
		echo "开始部署 $webname"
		add_yuming
		nginx_install_status
		install_ssltls
		certs_status

		docker run -d --name halo --restart always -p 8010:8090 -v /home/web/html/$yuming/.halo2:/root/.halo2 halohub/halo:2
		duankou=8010
		reverse_proxy

		nginx_web_on

			;;

		27)
		clear
		webname="AI绘画提示词生成器"
		#  "安装$webname"
		echo "开始部署 $webname"
		add_yuming
		nginx_install_status
		install_ssltls
		certs_status

		wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/html.conf
		sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
		nginx_http_on

		cd /home/web/html
		mkdir $yuming
		cd $yuming

		wget ${gh_proxy}github.com/kejilion/Website_source_code/raw/refs/heads/main/ai_prompt_generator.zip
		unzip $(ls -t *.zip | head -n 1)
		rm -f $(ls -t *.zip | head -n 1)

		docker exec nginx chmod -R nginx:nginx /var/www/html
		docker exec nginx nginx -s reload

		nginx_web_on

			;;

		28)
		ldnmp_Proxy_backend
			;;


		30)
		clear
		webname="静态站点"
		#  "安装$webname"
		echo "开始部署 $webname"
		add_yuming
		repeat_add_yuming
		nginx_install_status
		install_ssltls
		certs_status

		wget -O /home/web/conf.d/$yuming.conf ${gh_proxy}raw.githubusercontent.com/kejilion/nginx/main/html.conf
		sed -i "s/yuming.com/$yuming/g" /home/web/conf.d/$yuming.conf
		nginx_http_on

		cd /home/web/html
		mkdir $yuming
		cd $yuming


		clear
		echo -e "[${yellow}1/2${white}] 上传静态源码"
		echo "-------------"
		echo "目前只允许上传zip格式的源码包, 请将源码包放到/home/web/html/${yuming}目录下"
		read -e -p "也可以输入下载链接, 远程下载源码包, 直接回车将跳过远程下载： " url_download

		if [ -n "$url_download" ]; then
			wget "$url_download"
		fi

		unzip $(ls -t *.zip | head -n 1)
		rm -f $(ls -t *.zip | head -n 1)

		clear
		echo -e "[${yellow}2/2${white}] index.html所在路径"
		echo "-------------"
		# find "$(realpath .)" -name "index.html" -print
		find "$(realpath .)" -name "index.html" -print | xargs -I {} dirname {}

		read -e -p "请输入index.html的路径, 类似（/home/web/html/$yuming/index/）： " index_lujing

		sed -i "s#root /var/www/html/$yuming/#root $index_lujing#g" /home/web/conf.d/$yuming.conf
		sed -i "s#/home/web/#/var/www/#g" /home/web/conf.d/$yuming.conf

		docker exec nginx chmod -R nginx:nginx /var/www/html
		docker exec nginx nginx -s reload

		nginx_web_on

			;;

		31)
		ldnmp_web_status
		;;


		32)
		clear
		#  "LDNMP环境备份"

		local backup_filename="web_$(date +"%Y%m%d%H%M%S").tar.gz"
		echo -e "${yellow}正在备份 $backup_filename ...${white}"
		cd /home/ && tar czvf "$backup_filename" web

		while true; do
			clear
			echo "备份文件已创建: /home/$backup_filename"
			read -e -p "要传送备份数据到远程服务器吗？(Y/N): " choice
			case "$choice" in
			[Yy])
				read -e -p "请输入远端服务器IP:  " remote_ip
				if [ -z "$remote_ip" ]; then
				echo "错误: 请输入远端服务器IP."
				continue
				fi
				local latest_tar=$(ls -t /home/*.tar.gz | head -1)
				if [ -n "$latest_tar" ]; then
				ssh-keygen -f "/root/.ssh/known_hosts" -R "$remote_ip"
				sleep 2  # 添加等待时间
				scp -o StrictHostKeyChecking=no "$latest_tar" "root@$remote_ip:/home/"
				echo "文件已传送至远程服务器home目录."
				else
				echo "未找到要传送的文件."
				fi
				break
				;;
			[Nn])
				break
				;;
			*)
				echo -e "${red}无效选择, 请输入Y或N !${white}"
				sleep 1
				;;
			esac
		done
		;;

		33)
		clear
		#  "定时远程备份"
		read -e -p "输入远程服务器IP: " useip
		read -e -p "输入远程服务器密码: " usepasswd

		cd ~
		wget -O ${useip}_beifen.sh ${gh_proxy}raw.githubusercontent.com/kejilion/sh/main/beifen.sh > /dev/null 2>&1
		chmod +x ${useip}_beifen.sh

		sed -i "s/0.0.0.0/$useip/g" ${useip}_beifen.sh
		sed -i "s/123456/$usepasswd/g" ${useip}_beifen.sh

		echo "------------------------"
		echo "1. 每周备份                 2. 每天备份"
		read -e -p "请输入你的选择: " dingshi

		case $dingshi in
			1)
				check_crontab_installed
				read -e -p "选择每周备份的星期几 (0-6, 0代表星期日): " weekday
				(crontab -l ; echo "0 0 * * $weekday ./${useip}_beifen.sh") | crontab - > /dev/null 2>&1
				;;
			2)
				check_crontab_installed
				read -e -p "选择每天备份的时间（小时, 0-23）: " hour
				(crontab -l ; echo "0 $hour * * * ./${useip}_beifen.sh") | crontab - > /dev/null 2>&1
				;;
			*)
				break  # 跳出
				;;
		esac

		install sshpass

		;;

		34)
		root_use
		#  "LDNMP环境还原"
		echo "可用的站点备份"
		echo "-------------------------"
		ls -lt /home/*.gz | awk '{print $NF}'
		echo ""
		read -e -p  "回车键还原最新的备份,输入备份文件名还原指定的备份, 输入0退出：" filename

		if [ "$filename" == "0" ]; then
			break_end
			linux_ldnmp
		fi

		# 如果用户没有输入文件名, 使用最新的压缩包
		if [ -z "$filename" ]; then
			local filename=$(ls -t /home/*.tar.gz | head -1)
		fi

		if [ -n "$filename" ]; then
			cd /home/web/ > /dev/null 2>&1
			docker compose down > /dev/null 2>&1
			rm -rf /home/web > /dev/null 2>&1

			echo -e "${yellow}正在解压 $filename ...${white}"
			cd /home/ && tar -xzf "$filename"

			check_port
			dependency_check
			install_docker
			install_certbot
			install_ldnmp
		else
			echo "没有找到压缩包."
		fi

		;;

		35)
			web_security
			;;

		36)
			web_optimization
			;;


		37)
		root_use
		while true; do
			clear
			#  "更新LDNMP环境"
			echo "更新LDNMP环境"
			echo -e "${pink}------------------------${white}"
			ldnmp_v
			echo "发现新版本的组件"
			echo -e "${pink}------------------------${white}"
			check_docker_image_update nginx
			if [ -n "$update_status" ]; then
				echo -e "${yellow}nginx $update_status${white}"
			fi
			check_docker_image_update php
			if [ -n "$update_status" ]; then
				echo -e "${yellow}php $update_status${white}"
			fi
			check_docker_image_update mysql
			if [ -n "$update_status" ]; then
				echo -e "${yellow}mysql $update_status${white}"
			fi
			check_docker_image_update redis
			if [ -n "$update_status" ]; then
				echo -e "${yellow}redis $update_status${white}"
			fi
			echo -e "${pink}------------------------${white}"
			echo
			echo "1. 更新nginx               2. 更新mysql              3. 更新php              4. 更新redis"
			echo -e "${pink}------------------------${white}"
			echo "5. 更新完整环境"
			echo -e "${pink}------------------------${white}"
			echo -e "${yellow}0.     ${white}返回上一级菜单"
			echo -e "${pink}------------------------${white}"
			read -e -p "请输入你的选择: " sub_choice
			case $sub_choice in
				1)
				nginx_upgrade

					;;

				2)
				local ldnmp_pods="mysql"
				read -e -p "请输入${ldnmp_pods}版本号 （如: 8.0 8.3 8.4 9.0）（回车获取最新版）: " version
				local version=${version:-latest}

				cd /home/web/
				cp /home/web/docker-compose.yml /home/web/docker-compose1.yml
				sed -i "s/image: mysql/image: mysql:${version}/" /home/web/docker-compose.yml
				docker rm -f $ldnmp_pods
				docker images --filter=reference="$ldnmp_pods*" -q | xargs docker rmi > /dev/null 2>&1
				docker compose up -d --force-recreate $ldnmp_pods
				docker restart $ldnmp_pods
				cp /home/web/docker-compose1.yml /home/web/docker-compose.yml
				#  "更新$ldnmp_pods"
				echo "更新${ldnmp_pods}完成"

					;;
				3)
				local ldnmp_pods="php"
				read -e -p "请输入${ldnmp_pods}版本号 （如: 7.4 8.0 8.1 8.2 8.3）（回车获取最新版）: " version
				local version=${version:-8.3}
				cd /home/web/
				cp /home/web/docker-compose.yml /home/web/docker-compose1.yml
				sed -i "s/kjlion\///g" /home/web/docker-compose.yml > /dev/null 2>&1
				sed -i "s/image: php:fpm-alpine/image: php:${version}-fpm-alpine/" /home/web/docker-compose.yml
				docker rm -f $ldnmp_pods
				docker images --filter=reference="$ldnmp_pods*" -q | xargs docker rmi > /dev/null 2>&1
				docker images --filter=reference="kjlion/${ldnmp_pods}*" -q | xargs docker rmi > /dev/null 2>&1
				docker compose up -d --force-recreate $ldnmp_pods
				docker exec php chown -R www-data:www-data /var/www/html

				run_command docker exec php sed -i "s/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g" /etc/apk/repositories > /dev/null 2>&1

				docker exec php apk update
				curl -sL ${gh_proxy}github.com/mlocati/docker-php-extension-installer/releases/latest/download/install-php-extensions -o /usr/local/bin/install-php-extensions
				docker exec php mkdir -p /usr/local/bin/
				docker cp /usr/local/bin/install-php-extensions php:/usr/local/bin/
				docker exec php chmod +x /usr/local/bin/install-php-extensions
				docker exec php install-php-extensions mysqli pdo_mysql gd intl zip exif bcmath opcache redis imagick soap


				docker exec php sh -c 'echo "upload_max_filesize=50M " > /usr/local/etc/php/conf.d/uploads.ini' > /dev/null 2>&1
				docker exec php sh -c 'echo "post_max_size=50M " > /usr/local/etc/php/conf.d/post.ini' > /dev/null 2>&1
				docker exec php sh -c 'echo "memory_limit=512M" > /usr/local/etc/php/conf.d/memory.ini' > /dev/null 2>&1
				docker exec php sh -c 'echo "max_execution_time=1200" > /usr/local/etc/php/conf.d/max_execution_time.ini' > /dev/null 2>&1
				docker exec php sh -c 'echo "max_input_time=600" > /usr/local/etc/php/conf.d/max_input_time.ini' > /dev/null 2>&1
				docker exec php sh -c 'echo "max_input_vars=5000" > /usr/local/etc/php/conf.d/max_input_vars.ini' > /dev/null 2>&1

				fix_phpfpm_conf $ldnmp_pods

				docker restart $ldnmp_pods > /dev/null 2>&1
				cp /home/web/docker-compose1.yml /home/web/docker-compose.yml
				#  "更新$ldnmp_pods"
				echo "更新${ldnmp_pods}完成"

					;;
				4)
				local ldnmp_pods="redis"
				cd /home/web/
				docker rm -f $ldnmp_pods
				docker images --filter=reference="$ldnmp_pods*" -q | xargs docker rmi > /dev/null 2>&1
				docker compose up -d --force-recreate $ldnmp_pods
				docker restart $ldnmp_pods > /dev/null 2>&1
				restart_redis
				#  "更新$ldnmp_pods"
				echo "更新${ldnmp_pods}完成"

					;;
				5)
					read -e -p "$(echo -e "${yellow}提示: ${white}长时间不更新环境的用户, 请慎重更新LDNMP环境, 会有数据库更新失败的风险.确定更新LDNMP环境吗？(Y/N): ")" choice
					case "$choice" in
					[Yy])
						#  "完整更新LDNMP环境"
						cd /home/web/
						docker compose down --rmi all

						check_port
						dependency_check
						install_docker
						install_certbot
						install_ldnmp
						;;
					*)
						;;
					esac
					;;
				*)
					break
					;;
			esac
			break_end
			done
			;;

		38)
			root_use
			#  "卸载LDNMP环境"
			read -e -p "$(echo -e "${red}强烈建议：${white}先备份全部网站数据, 再卸载LDNMP环境.确定删除所有网站数据吗？(Y/N): ")" choice
			case "$choice" in
			[Yy])
				cd /home/web/
				docker compose down --rmi all
				docker compose -f docker-compose.phpmyadmin.yml down > /dev/null 2>&1
				docker compose -f docker-compose.phpmyadmin.yml down --rmi all > /dev/null 2>&1
				rm -rf /home/web
				;;
			[Nn])

				;;
			*)
				echo -e "${red}无效选择, 请输入Y或N !${white}"
				sleep 1
				;;
			esac
			;;

		0)
			return_to_menu
		;;

		*)
			echo -e "${red}无效选择, 请重新输入 !${white}"
			sleep 1
			;;
		esac
	done
}
