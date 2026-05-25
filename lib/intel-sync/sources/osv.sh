# ⚡ Low Watt Labs
# OSV sync - npm and PyPI ecosystems
# Downloads OSV advisories and builds a consolidated index for fast lookups
set -euo pipefail

# Run at low priority so this never starves other processes
renice -n 15 $$ >/dev/null 2>&1 || true
ionice -c 3 -p $$ 2>/dev/null || true

source "$(dirname "$0")/../../common/config.sh"
source "$(dirname "$0")/../../common/colors.sh"
source "$(dirname "$0")/../../common/log.sh"
source "$(dirname "$0")/../../common/utils.sh"

INTEL_DIR="${FRISK_INTEL_DIR}"
OSV_DIR="${INTEL_DIR}/osv"
MANIFEST_PY="$(dirname "$0")/../manifest.py"
URL_BASE="https://osv-vulnerabilities.storage.googleapis.com"

ECOSYSTEMS=("npm" "PyPI")
total=0
any_fail=0

for eco in "${ECOSYSTEMS[@]}"; do
    log_info "Syncing OSV $eco..."
    eco_dir="${OSV_DIR}/${eco}"
    mkdir -p "$eco_dir"

    zip_url="${URL_BASE}/${eco}/all.zip"
    zip_tmp=$(mktemp "${TMPDIR:-/tmp}/osv-${eco}.XXXXXX.zip")

    if curl -fsSL --max-time 300 --retry 3 --retry-delay 5 "$zip_url" -o "$zip_tmp"; then
        extract_tmp=$(mktemp -d "${TMPDIR:-/tmp}/osv-${eco}-extract.XXXXXX")
        if unzip -q -o "$zip_tmp" -d "$extract_tmp" 2>/dev/null; then
            # Clean old JSON files and broken symlinks before replacing
            find "$eco_dir" -maxdepth 1 -name '*.json' -delete 2>/dev/null || true
            find "$eco_dir" -maxdepth 1 -type l ! -exec test -e {} \; -delete 2>/dev/null || true
            find "$extract_tmp" -maxdepth 1 -name '*.json' -exec mv -t "$eco_dir" {} +
            count=$(find "$eco_dir" -maxdepth 1 -name '*.json' | wc -l)
            total=$((total + count))
            log_info "OSV $eco: $count advisories"
        else
            any_fail=1
            log_warn "OSV $eco: extraction failed"
        fi
        rm -rf "$extract_tmp"
    else
        any_fail=1
        log_warn "OSV $eco: download failed"
    fi
    rm -f "$zip_tmp"
done

# Build consolidated index: package_name -> list of advisory filenames
log_info "Building OSV package index..."
for eco in "${ECOSYSTEMS[@]}"; do
    eco_dir="${OSV_DIR}/${eco}"
    index_file="${eco_dir}/index.json"

    if [[ -d "$eco_dir" ]]; then
        # Build index using Python for speed
        # Pass both eco_dir and index_file as arguments to avoid bash-in-Python variable scoping
        index_count=$(python3 -c "
import json, os, sys
eco_dir = sys.argv[1]
index_path = sys.argv[2]
index = {}
for fname in os.listdir(eco_dir):
    if not fname.endswith('.json') or fname == 'index.json':
        continue
    fpath = os.path.join(eco_dir, fname)
    try:
        with open(fpath) as f:
            adv = json.load(f)
        for affected in adv.get('affected', []):
            pkg = affected.get('package', {})
            name = pkg.get('name', '')
            if name:
                key = name.lower()
                if key not in index:
                    index[key] = []
                index[key].append(fname)
    except (json.JSONDecodeError, KeyError, OSError):
        continue
# Write index atomically
tmp = index_path + '.new'
with open(tmp, 'w') as f:
    json.dump(index, f)
os.rename(tmp, index_path)
print(len(index))
" "$eco_dir" "$index_file")
        log_info "OSV $eco index: $index_count packages"
    fi
done

status="success"
[[ $any_fail -eq 1 ]] && status="partial"
python3 "$MANIFEST_PY" update osv "$total" "$status"
if [[ $any_fail -eq 0 ]]; then
    echo -e "${CHECKMARK} OSV: ${total} advisories (npm + PyPI, indexed)"
else
    echo -e "${WARNMARK} OSV: partial sync — ${total} advisories"
fi