docker_ps_names=$'\n'komari$'\n'navidrome$'\n'
nl=$'\n'
d_name='komari'
if [[ "$docker_ps_names" == *"${nl}${d_name}${nl}"* ]]; then
  echo 'Matched'
else
  echo 'Not Matched'
fi
