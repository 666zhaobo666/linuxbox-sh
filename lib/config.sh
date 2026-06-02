load_linuxbox_config() {
	if [ -f "$SCRIPT_CONFIG_FILE" ]; then
		# shellcheck disable=SC1090
		. "$SCRIPT_CONFIG_FILE"
	fi
	key="${key:-${LINUXBOX_KEY:-j}}"
}

save_linuxbox_config() {
	mkdir -p "$SCRIPT_HOME"
	{
		echo "SCRIPT_BRANCH=\"$SCRIPT_BRANCH\""
		echo "key=\"$key\""
	} > "$SCRIPT_CONFIG_FILE"
}
