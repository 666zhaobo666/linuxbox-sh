###########################################################################
########################### 四、基础工具管理 ###############################
# 从 kejilion-sh 的 linux_tools 迁移, 已适配 linuxbox-sh 的颜色变量
# 入口函数: linux_basic_tools (主菜单第 4 项调用)
# 适配说明:
#   - 颜色变量: gl_kjlan→cyan, gl_bai→white, gl_huang→yellow
#   - 去掉 kejilion 专属的 send_stats 统计上报
#   - 入口函数重命名为 linux_basic_tools, 避免与 system_tools.sh 的 linux_tools 撞名

linux_basic_tools() {

  while true; do
	  clear
	  echo -e "基础工具"

	  tools=(
		curl wget sudo socat htop iftop unzip tar tmux ffmpeg
		btop ranger ncdu fzf cmatrix sl bastet nsnake ninvaders
		vim nano git
	  )

	  if command -v apt >/dev/null 2>&1; then
		PM="apt"
	  elif command -v dnf >/dev/null 2>&1; then
		PM="dnf"
	  elif command -v yum >/dev/null 2>&1; then
		PM="yum"
	  elif command -v pacman >/dev/null 2>&1; then
		PM="pacman"
	  elif command -v apk >/dev/null 2>&1; then
		PM="apk"
	  elif command -v zypper >/dev/null 2>&1; then
		PM="zypper"
	  elif command -v opkg >/dev/null 2>&1; then
		PM="opkg"
	  elif command -v pkg >/dev/null 2>&1; then
		PM="pkg"
	  else
		echo "未识别的包管理器"
		break_end
		return
	  fi

	  echo "使用包管理器: $PM"
	  echo -e "${cyan}------------------------${white}"

	  for ((i=0; i<${#tools[@]}; i+=2)); do
		# 左列
		if command -v "${tools[i]}" >/dev/null 2>&1; then
		  left=$(printf "✅ %-12s 已安装" "${tools[i]}")
		else
		  left=$(printf "❌ %-12s 未安装" "${tools[i]}")
		fi

		# 右列（防止数组越界）
		if [[ -n "${tools[i+1]}" ]]; then
		  if command -v "${tools[i+1]}" >/dev/null 2>&1; then
			right=$(printf "✅ %-12s 已安装" "${tools[i+1]}")
		  else
			right=$(printf "❌ %-12s 未安装" "${tools[i+1]}")
		  fi
		  printf "%-42s %s\n" "$left" "$right"
		else
		  printf "%s\n" "$left"
		fi
	  done

	  echo -e "${cyan}------------------------"
	  echo -e "${cyan}1.   ${white}curl 下载工具 ${yellow}★${white}                   ${cyan}2.   ${white}wget 下载工具 ${yellow}★${white}"
	  echo -e "${cyan}3.   ${white}sudo 超级管理权限工具             ${cyan}4.   ${white}socat 通信连接工具"
	  echo -e "${cyan}5.   ${white}htop 系统监控工具                 ${cyan}6.   ${white}iftop 网络流量监控工具"
	  echo -e "${cyan}7.   ${white}unzip ZIP压缩解压工具             ${cyan}8.   ${white}tar GZ压缩解压工具"
	  echo -e "${cyan}9.   ${white}tmux 多路后台运行工具             ${cyan}10.  ${white}ffmpeg 视频编码直播推流工具"
	  echo -e "${cyan}------------------------"
	  echo -e "${cyan}11.  ${white}btop 现代化监控工具 ${yellow}★${white}             ${cyan}12.  ${white}ranger 文件管理工具"
	  echo -e "${cyan}13.  ${white}ncdu 磁盘占用查看工具             ${cyan}14.  ${white}fzf 全局搜索工具"
	  echo -e "${cyan}15.  ${white}vim 文本编辑器                    ${cyan}16.  ${white}nano 文本编辑器 ${yellow}★${white}"
	  echo -e "${cyan}17.  ${white}git 版本控制系统                  ${cyan}18.  ${white}opencode AI编程助手 ${yellow}★${white}"
	  echo -e "${cyan}------------------------"
	  echo -e "${cyan}21.  ${white}黑客帝国屏保                      ${cyan}22.  ${white}跑火车屏保"
	  echo -e "${cyan}26.  ${white}俄罗斯方块小游戏                  ${cyan}27.  ${white}贪吃蛇小游戏"
	  echo -e "${cyan}28.  ${white}太空入侵者小游戏"
	  echo -e "${cyan}------------------------"
	  echo -e "${cyan}31.  ${white}全部安装                          ${cyan}32.  ${white}全部安装（不含屏保和游戏）${yellow}★${white}"
	  echo -e "${cyan}33.  ${white}全部卸载"
	  echo -e "${cyan}------------------------"
	  echo -e "${cyan}41.  ${white}安装指定工具                      ${cyan}42.  ${white}卸载指定工具"
	  echo -e "${cyan}------------------------"
	  echo -e "${cyan}0.   ${white}返回主菜单"
	  echo -e "${cyan}------------------------${white}"
	  read -e -p "请输入你的选择: " sub_choice

	  case $sub_choice in
		  1)
			  clear
			  install curl
			  clear
			  echo "工具已安装，使用方法如下："
			  curl --help
			  ;;
		  2)
			  clear
			  install wget
			  clear
			  echo "工具已安装，使用方法如下："
			  wget --help
			  ;;
			3)
			  clear
			  install sudo
			  clear
			  echo "工具已安装，使用方法如下："
			  sudo --help
			  ;;
			4)
			  clear
			  install socat
			  clear
			  echo "工具已安装，使用方法如下："
			  socat -h
			  ;;
			5)
			  clear
			  install htop
			  clear
			  htop
			  ;;
			6)
			  clear
			  install iftop
			  clear
			  iftop
			  ;;
			7)
			  clear
			  install unzip
			  clear
			  echo "工具已安装，使用方法如下："
			  unzip
			  ;;
			8)
			  clear
			  install tar
			  clear
			  echo "工具已安装，使用方法如下："
			  tar --help
			  ;;
			9)
			  clear
			  install tmux
			  clear
			  echo "工具已安装，使用方法如下："
			  tmux --help
			  ;;
			10)
			  clear
			  install ffmpeg
			  clear
			  echo "工具已安装，使用方法如下："
			  ffmpeg --help
			  ;;

			11)
			  clear
			  install btop
			  clear
			  btop
			  ;;
			12)
			  clear
			  install ranger
			  cd /
			  clear
			  ranger
			  cd ~
			  ;;
			13)
			  clear
			  install ncdu
			  cd /
			  clear
			  ncdu
			  cd ~
			  ;;
			14)
			  clear
			  install fzf
			  cd /
			  clear
			  fzf
			  cd ~
			  ;;
			15)
			  clear
			  install vim
			  cd /
			  clear
			  vim -h
			  cd ~
			  ;;
			16)
			  clear
			  install nano
			  cd /
			  clear
			  nano -h
			  cd ~
			  ;;


			17)
			  clear
			  install git
			  cd /
			  clear
			  git --help
			  cd ~
			  ;;

			18)
			  clear
			  cd ~
			  curl -fsSL https://opencode.ai/install | bash
			  source ~/.bashrc
			  source ~/.profile
			  opencode
			  ;;


			21)
			  clear
			  install cmatrix
			  clear
			  cmatrix
			  ;;
			22)
			  clear
			  install sl
			  clear
			  if command -v sl >/dev/null 2>&1; then
			    sl
			  else
			    echo "sl 安装失败或不存在，请手动安装"
			  fi
			  ;;
			26)
			  clear
			  install bastet
			  clear
			  if command -v bastet >/dev/null 2>&1; then
			    bastet
			  else
			    echo "bastet 安装失败或不存在，请手动安装"
			  fi
			  ;;
			27)
			  clear
			  install nsnake
			  clear
			  if command -v nsnake >/dev/null 2>&1; then
			    nsnake
			  else
			    echo "nsnake 安装失败或不存在，请手动安装"
			  fi
			  ;;

			28)
			  clear
			  install ninvaders
			  clear
			  if command -v ninvaders >/dev/null 2>&1; then
			    ninvaders
			  else
			    echo "ninvaders 安装失败或不存在，请手动安装"
			  fi
			  ;;

		  31)
			  clear
			  install curl wget sudo socat htop iftop unzip tar tmux ffmpeg btop ranger ncdu fzf cmatrix sl bastet nsnake ninvaders vim nano git
			  ;;

		  32)
			  clear
			  install curl wget sudo socat htop iftop unzip tar tmux ffmpeg btop ranger ncdu fzf vim nano git
			  ;;


		  33)
			  clear
			  remove htop iftop tmux ffmpeg btop ranger ncdu fzf cmatrix sl bastet nsnake ninvaders vim nano git
			  opencode uninstall
			  rm -rf ~/.opencode
			  ;;

		  41)
			  clear
			  read -e -p "请输入安装的工具名（wget curl sudo htop）: " installname
			  install $installname
			  ;;
		  42)
			  clear
			  read -e -p "请输入卸载的工具名（htop ufw tmux cmatrix）: " removename
			  remove $removename
			  ;;

		  0)
			  return
			  ;;

		  *)
			  echo -e "${red}无效的输入!${white}"
			  ;;
	  esac
	  break_end
  done



}
