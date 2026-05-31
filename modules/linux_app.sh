linux_app() {

	while true; do
		clear
		echo -e "${green}===== 应用市场 =====${white}"
		echo ""
		docker_tato
		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		echo -e "${cyan}1.  ${white}1Panel面板             ${cyan}2.  ${white}宝塔面板                 ${cyan}3.  ${white}aaPanel面板"
		echo -e "${cyan}4.  ${white}NginxProxyManager面板  ${cyan}5.  ${white}OpenList面板             ${cyan}6.  ${white}WebTop远程桌面网页版"
		echo -e "${cyan}7.  ${white}哪吒探针               ${cyan}8.  ${white}qbittorrent离线下载      ${cyan}9.  ${white}Poste.io邮件服务器程序"
		echo -e "${cyan}10. ${white}青龙面板               ${cyan}11. ${white}Code-Server(网页vscode)  ${cyan}12. ${white}Looking Glass(测速面板)"
		echo -e "${cyan}13. ${white}雷池WAF防火墙面板      ${cyan}14. ${white}onlyoffice在线办公OFFICE ${cyan}15. ${white}UptimeKuma监控工具"
		echo -e "${cyan}16. ${white}Memos网页备忘录        ${cyan}17. ${white}drawio免费的在线图表软件 ${cyan}18. ${white}Sun-Panel导航面板"
		echo -e "${cyan}19. ${white}webssh网页版SSH连接工具${cyan}20. ${white}LobeChatAI聊天聚合网站   ${cyan}21. ${white}MyIP工具箱"
		echo -e "${cyan}22. ${white}ghproxy(GitHub加速站)  ${cyan}23. ${white}AllinSSL证书管理平台     ${cyan}24. ${white}DDNS-GO"
		echo -e "${cyan}25. ${white}Lucky                  ${cyan}26. ${white}LibreTV私有影视          ${cyan}27. ${white}MoonTV私有影视"
		echo -e "${cyan}28. ${white}Melody音乐精灵         ${cyan}29. ${white}Beszel服务器监控         ${cyan}30. ${white}SyncTV一起看片神器"
		echo -e "${cyan}31. ${white}X-UI面板               ${cyan}32. ${white}3X-UI面板                ${cyan}33. ${white}Microsoft 365 E5 Renew X"
		echo -e "${cyan}34. ${white}DecoTV私有影视         ${cyan}35. ${white}Drawnix在线白板"
		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		echo -e "${yellow}0.   ${white}返回主菜单"
		echo -e "${pink}------------------------------------------------------------------------------------${white}"
		read -e -p "请输入你的选择: " sub_choice

		case $sub_choice in
		1)
			1panel_app ;;
		2)
			bt_app ;;
		3)
			aapanel_app ;;
		4)
			npm_app ;;
		5)
			openlist_app ;;
		6)
			webtop_app ;;
		7)
			nezha_app ;;
		8)
			qb_app ;;
		9)
			poste_mail_app ;;
		10)
			qinglong_app ;;
		11)
			code_server_app ;;
		12)
			looking_glass_app ;;
		13)
			safeline_app ;;
		14)
			onlyoffice_app ;;
		15)
			uptimekuma_app ;;
		16)
			memos_app ;;
		17)
			drawio_app ;;
		18)
			sun_panel_app ;;
		19)
			webssh_app ;;
		20)
			lobe_chat ;;
		21)
			myip_app ;;
		22)
			ghproxy_app ;;
		23)
			allinssl_app ;;
		24)
			ddnsgo_app ;;
		25)
			lucky_app ;;
		26)
			libretv_app ;;
		27)
			moontv_app ;;
		28)
			melody_app ;;
		29)
			beszel_app ;;
		30)
			synctv_app ;;
		31)
			xui_app ;;
		32)
			3xui_app ;;
		33)
			e5_renew_x_app ;;
		34)
			decotv_app ;;
		35)
			drawnix_app ;;
		0)
			break
			;;
		*)
			echo -e "${red}无效选择, 请重新输入 !${white}"
			sleep 1
			;;
		esac
	done
}


#############################################################################
############################### 九、Dev环境管理###############################
