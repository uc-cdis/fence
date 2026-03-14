#!/usr/bin/env bash
set -euo pipefail

# -----------------------------
# Config (adjust if needed)
# -----------------------------
ORG="${ORG:-$(gh api user | jq -r .login)}"   # default to your account
SOURCE="uc-cdis/fence"
TARGET_REPO="${TARGET_REPO:-presigned-urls}"
BRANCH="presign-only"
WORKDIR="${WORKDIR:-$(pwd)}"

echo "==> Using ORG: $ORG"
echo "==> Source: $SOURCE"
echo "==> Target repo: $ORG/$TARGET_REPO"
echo "==> Workdir: $WORKDIR"

# -----------------------------
# 1) Fork fence & clone it
# -----------------------------
if ! gh repo view "$ORG/fence" >/dev/null 2>&1; then
  echo "==> Forking $SOURCE into $ORG/fence"
  gh repo fork "$SOURCE" --org "$ORG" --remote=false --default-branch-only
fi

if [ ! -d "$WORKDIR/fence" ]; then
  echo "==> Cloning fork: $ORG/fence"
  git clone "https://github.com/$ORG/fence.git" "$WORKDIR/fence"
fi

cd "$WORKDIR/fence"
git fetch --all --tags
git checkout -B "$BRANCH"

# -----------------------------
# 2) Create presigned-urls repo
# -----------------------------
if ! gh repo view "$ORG/$TARGET_REPO" >/dev/null 2>&1; then
  echo "==> Creating $ORG/$TARGET_REPO"
  gh repo create "$ORG/$TARGET_REPO" --private -y
fi

TARGET_DIR="$WORKDIR/$TARGET_REPO"
rm -rf "$TARGET_DIR"
mkdir -p "$TARGET_DIR"
echo "==> Copying fence into $TARGET_REPO (shallow subset)"
rsync -a --exclude '.git' ./ "$TARGET_DIR/"

cd "$TARGET_DIR"

# -----------------------------
# 3) Strip non-data endpoints
#    Keep ONLY: health/status + data
# -----------------------------
echo "==> Removing non-data blueprints & auth surfaces"

# Common blueprint dirs in Fence (conservative remove list)
rm -rf fence/blueprints/{admin,oauth2,login,link,openid,ga4gh,google,home,counts,download,metadata,devices,storage,creds} 2>/dev/null || true
# Keep: data (signed URLs), status (healthz)
# Note: some Fence versions have health under 'blueprints/status' and/or 'blueprints/health'

# If both exist, keep both; otherwise keep whichever is present
KEEP_DIRS=()
[ -d fence/blueprints/data ] && KEEP_DIRS+=("fence/blueprints/data")
[ -d fence/blueprints/status ] && KEEP_DIRS+=("fence/blueprints/status")
[ -d fence/blueprints/health ] && KEEP_DIRS+=("fence/blueprints/health")

# Remove any other blueprint subdirs not in KEEP_DIRS
for d in fence/blueprints/*; do
  [ -d "$d" ] || continue
  skip=false
  for k in "${KEEP_DIRS[@]}"; do
    if [ "$d" = "$k" ]; then skip=true; break; fi
  done
  if [ "$skip" = false ]; then
    rm -rf "$d"
  fi
done

# -----------------------------
# 4) Patch app: register ONLY health/status + data blueprints
#    Fence has an app factory in fence/__init__.py or fence/app.py depending on version.
# -----------------------------
APP_MAIN=""
if [ -f fence/__init__.py ]; then
  APP_MAIN="fence/__init__.py"
elif [ -f fence/app.py ]; then
  APP_MAIN="fence/app.py"
else
  echo "Could not find app entry (fence/__init__.py or fence/app.py). Exiting."
  exit 1
fi

echo "==> Patching $APP_MAIN to limit blueprint registration"

# Backup
cp "$APP_MAIN" "$APP_MAIN.bak"

# Create a focused registrar module that only imports status/health + data
mkdir -p fence/_presign_bootstrap
cat > fence/_presign_bootstrap/blueprints_presign_only.py <<'PY'
from flask import Blueprint

def register_presign_blueprints(app):
    """
    Register only the health/status & data blueprints.
    This function is imported and invoked from the app factory.
    """
    # Different Fence versions expose status/health under different modules.
    # Try a few known imports, tolerate failures at import-time by guarding.
    registered = []

    # health/status
    for mod, attr in [
        ("fence.blueprints.status", "bp"),
        ("fence.blueprints.status.blueprint", "blueprint"),
        ("fence.blueprints.health", "bp"),
        ("fence.blueprints.health.blueprint", "blueprint"),
    ]:
        try:
            m = __import__(mod, fromlist=[attr])
            bp = getattr(m, attr)
            app.register_blueprint(bp)
            registered.append(f"{mod}:{attr}")
            break
        except Exception:
            continue

    # data (signed URL endpoints)
    for mod, attr in [
        ("fence.blueprints.data", "data_blueprint"),
        ("fence.blueprints.data.blueprint", "blueprint"),
        ("fence.blueprints.data", "bp"),
    ]:
        try:
            m = __import__(mod, fromlist=[attr])
            bp = getattr(m, attr)
            app.register_blueprint(bp, url_prefix="/data")
            registered.append(f"{mod}:{attr}")
            break
        except Exception:
            continue

    if not registered:
        app.logger.warning("No blueprints were registered by presign-only bootstrap.")
    else:
        app.logger.info("Presign-only registered blueprints: %s", registered)
PY

# Inject a call to register_presign_blueprints into the app factory:
# We'll search for 'def create_app' and ensure our call happens AFTER the Flask app is created but BEFORE returning it.
python3 - <<'PY'
import io, re, sys, pathlib
p = pathlib.Path("fence/__init__.py") if pathlib.Path("fence/__init__.py").exists() else pathlib.Path("fence/app.py")
src = p.read_text()
# Heuristic: find create_app(...): the first 'return app' after creation; insert our import+call near app setup.
lines = src.splitlines()
out = []
inserted_import = False
inserted_call = False
app_var = "app"
for i, line in enumerate(lines):
    if not inserted_import and line.startswith("def create_app"):
        out.append("from fence._presign_bootstrap.blueprints_presign_only import register_presign_blueprints")
        inserted_import = True
    out.append(line)
    # Attempt to detect where 'app =' occurs
    if not inserted_call and re.search(r"\bapp\s*=\s*Flask\(", line):
        # wait to insert call a few lines later to ensure extensions/config initialized
        out.append("# presign-only: blueprints limited to health/status + data")
        out.append("register_presign_blueprints(app)")
        inserted_call = True

# Fallback: if no 'app = Flask(' pattern found, just append at end of create_app
if inserted_import and not inserted_call:
    for idx, l in enumerate(out):
        if l.startswith("def create_app"):
            # find end of function (naive by 'return app')
            for j in range(idx, len(out)):
                if re.search(r"return\s+app\b", out[j]):
                    out.insert(j, "    # presign-only: blueprints limited to health/status + data")
                    out.insert(j+1, "    register_presign_blueprints(app)")
                    inserted_call = True
                    break
            break

p.write_text("\n".join(out))
PY

# -----------------------------
# 5) Lighten dependencies (optional best-effort)
# -----------------------------
echo "==> Pruning optional deps (best-effort)"
if [ -f requirements.txt ]; then
  # Keep core; remove social-login/admin-only extras heuristically
  grep -E 'flask|boto3|requests|six|pyjwt|cryptography|authlib|werkzeug|blinker|gunicorn|gevent|psycopg2|psycopg2-binary' requirements.txt \
    > requirements-presign.txt || true
fi

# -----------------------------
# 6) Add a tiny route lister for verification
# -----------------------------
cat > tools/print_routes.py <<'PY'
import importlib
from pprint import pprint

def main():
    # Try standard create_app import
    try:
        from fence import create_app
    except Exception as e:
        print("Failed to import create_app from fence:", e)
        return
    app = create_app()
    routes = sorted([(r.rule, ",".join(r.methods)) for r in app.url_map.iter_rules()])
    for rule, methods in routes:
        print(f"{methods:30s}  {rule}")
    print("\nNOTE: You should only see /_status or /healthz and /data/* routes.")

if __name__ == "__main__":
    main()
PY

# -----------------------------
# 7) Repo scaffolding
# -----------------------------
cat > README.md <<'MD'
# presigned-urls (Fence fork: presign-only)

This service is a **presign-only** fork of Fence: it exposes only **health** and **/data** endpoints (download/upload, including multipart) for high-throughput presigned URL generation.

## What was removed
- All non-`/data` user/account/admin OAuth and UI surfaces
- All admin/identity/login/GA4GH/etc. blueprints
- Only **status/health** and **data** blueprints remain

## Verify routes
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-presign.txt || pip install flask
python tools/print_routes.py
