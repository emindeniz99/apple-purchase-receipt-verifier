while read repo ver; do
  r=$(echo $repo | cut -d/ -f1-2)
  tags=$(git ls-remote --tags --refs https://github.com/$r.git 2>/dev/null | sed 's#.*refs/tags/##' | grep -E '^v?[0-9]+(\.[0-9]+)*$' | sort -V)
  newer=$(printf '%s\n' $tags | awk -v v="$ver" 'BEGIN{} {print}' | sort -V | awk -v v="$ver" '$0==v{f=1;next} f')
  newer=$(echo $newer | tr ' ' '\n' | grep -vE '^v?[0-9]+$' | tr '\n' ' ')
  echo "$repo $ver -> ${newer:-none}"
done
