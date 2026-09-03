#!/bin/bash
#
# BBSFirewall - TLS certificate setup for the web config editor
# https://github.com/SysopNetwork/BBSFirewall
#
# The config editor runs its own HTTPS listener (default port 8443) with its
# own certificate, kept separate from the port-443 web redirect cert. This
# script gets that certificate into ./certs/config-editor/.
#
# Two modes:
#
#   Let's Encrypt (default) — a real, browser-trusted cert for a public
#   hostname. Uses certbot's webroot method through BBSFirewall's port-80
#   redirect server, so there is no downtime. Installs a renewal hook.
#
#     bash setup-config-cert.sh admin.example.com
#     bash setup-config-cert.sh admin.example.com --email you@example.com
#     bash setup-config-cert.sh admin.example.com --renew
#
#   Self-signed (--self-signed) — an openssl-generated cert for when the editor
#   is reached by bare IP or an internal hostname that Let's Encrypt cannot
#   validate. Browsers show a one-time trust warning.
#
#     bash setup-config-cert.sh 95.182.86.146 --self-signed
#     bash setup-config-cert.sh bfd1.internal --self-signed
#
# Requirements (Let's Encrypt mode):
#   - BBSFirewall running with WEB_REDIRECT_ENABLED=true
#   - Port 80 reachable from the internet
#   - Run as root or with sudo
#   - DNS for the hostname already points at this server
#

set -euo pipefail

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BBSFW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="$BBSFW_DIR/certs"
EDITOR_CERTS_DIR="$CERTS_DIR/config-editor"
WEBROOT="$CERTS_DIR/webroot"
PM2_APP_NAME="bbsfirewall"

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLU}[INFO]${NC}  $*"; }
ok()    { echo -e "${GRN}[OK]${NC}    $*"; }
warn()  { echo -e "${YLW}[WARN]${NC}  $*"; }
die()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------
DOMAIN=""
EMAIL=""
RENEW=false
SELF_SIGNED=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --email)       EMAIL="$2"; shift 2 ;;
    --renew)       RENEW=true; shift ;;
    --self-signed) SELF_SIGNED=true; shift ;;
    -*)            die "Unknown option: $1" ;;
    *)             DOMAIN="$1"; shift ;;
  esac
done

echo ""
echo "  BBSFirewall - Config Editor Certificate Setup"
echo "  ============================================="
echo ""

mkdir -p "$EDITOR_CERTS_DIR"

# ---------------------------------------------------------------------------
# Self-signed mode
# ---------------------------------------------------------------------------
if [[ "$SELF_SIGNED" == "true" ]]; then
  command -v openssl &>/dev/null || die "openssl not found — install it or use Let's Encrypt mode"
  [[ -n "$DOMAIN" ]] || die "Provide a CN (hostname or IP): bash setup-config-cert.sh <host> --self-signed"

  # Put the value in a SAN so modern browsers accept it. IP vs DNS matters.
  if [[ "$DOMAIN" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$DOMAIN" == *:* ]]; then
    SAN="IP:$DOMAIN"
  else
    SAN="DNS:$DOMAIN"
  fi

  info "Generating a self-signed certificate for $DOMAIN (SAN: $SAN)"
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$EDITOR_CERTS_DIR/privkey.pem" \
    -out    "$EDITOR_CERTS_DIR/fullchain.pem" \
    -subj   "/CN=$DOMAIN" \
    -addext "subjectAltName=$SAN"
  chmod 640 "$EDITOR_CERTS_DIR/privkey.pem"
  ok "Self-signed certificate written to $EDITOR_CERTS_DIR"

  echo ""
  echo "  Add these lines to your .env:"
  echo ""
  echo -e "  ${GRN}CONFIG_EDITOR_ENABLED=true${NC}"
  echo -e "  ${GRN}CONFIG_EDITOR_PORT=8443${NC}"
  echo -e "  ${GRN}CONFIG_EDITOR_CERT_PATH=$EDITOR_CERTS_DIR/fullchain.pem${NC}"
  echo -e "  ${GRN}CONFIG_EDITOR_KEY_PATH=$EDITOR_CERTS_DIR/privkey.pem${NC}"
  echo ""
  echo "  Browsers will show a trust warning on first visit — expected for a"
  echo "  self-signed cert. Then restart BBSFirewall (pm2 restart $PM2_APP_NAME)."
  echo ""
  exit 0
fi

# ---------------------------------------------------------------------------
# Let's Encrypt mode
# ---------------------------------------------------------------------------
[[ "$(id -u)" -eq 0 ]] || die "This script must be run as root. Try: sudo bash setup-config-cert.sh $DOMAIN"

if [[ "$RENEW" == "false" ]]; then
  [[ -n "$DOMAIN" ]] || die "No hostname specified. Usage: bash setup-config-cert.sh admin.example.com"
fi

# Install certbot if needed
if ! command -v certbot &>/dev/null; then
  info "certbot not found — installing..."
  if command -v apt-get &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq certbot
  elif command -v yum &>/dev/null; then
    yum install -y certbot
  elif command -v dnf &>/dev/null; then
    dnf install -y certbot
  else
    die "Could not install certbot automatically. See https://certbot.eff.org"
  fi
  ok "certbot installed"
else
  ok "certbot is already installed ($(certbot --version 2>&1 | head -1))"
fi

# Renewal mode
if [[ "$RENEW" == "true" ]]; then
  info "Renewing all certificates..."
  certbot renew --webroot --webroot-path "$WEBROOT" --quiet

  info "Restarting BBSFirewall to load renewed certificates..."
  if command -v pm2 &>/dev/null; then
    pm2 restart "$PM2_APP_NAME" --silent
    ok "BBSFirewall restarted via pm2"
  else
    warn "pm2 not found — restart BBSFirewall manually to load the new cert"
  fi
  ok "Renewal complete"
  exit 0
fi

# Fresh issuance
info "Hostname: $DOMAIN"
info "Webroot:  $WEBROOT"

mkdir -p "$WEBROOT/.well-known/acme-challenge"
ok "ACME webroot ready"

if command -v ss &>/dev/null; then
  if ! ss -tlnp | grep -q ':80 '; then
    warn "Nothing appears to be listening on port 80."
    warn "BBSFirewall's HTTP redirect server (WEB_REDIRECT_ENABLED=true) must be"
    warn "running so certbot can verify the domain over webroot."
    echo ""
    read -rp "  Continue anyway? [y/N] " confirm
    [[ "${confirm,,}" == "y" ]] || exit 1
  fi
fi

CERTBOT_ARGS=(
  certonly
  --webroot
  --webroot-path "$WEBROOT"
  --domain "$DOMAIN"
  --agree-tos
  --non-interactive
  --cert-name "bbsfirewall-config-editor"
)

if [[ -n "$EMAIL" ]]; then
  CERTBOT_ARGS+=(--email "$EMAIL")
else
  warn "No email address provided — you won't get expiry warnings."
  CERTBOT_ARGS+=(--register-unsafely-without-email)
fi

info "Running certbot..."
certbot "${CERTBOT_ARGS[@]}"

CERT_DIR="/etc/letsencrypt/live/bbsfirewall-config-editor"
[[ -f "$CERT_DIR/fullchain.pem" ]] || die "Certificate not found at $CERT_DIR — certbot may have failed"
[[ -f "$CERT_DIR/privkey.pem"   ]] || die "Private key not found at $CERT_DIR — certbot may have failed"
ok "Certificate issued to $CERT_DIR"

# Copy into the editor's cert directory (copy, not symlink, so BBSFirewall can
# read them without root). The renewal hook keeps these copies current.
cp "$CERT_DIR/fullchain.pem" "$EDITOR_CERTS_DIR/fullchain.pem"
cp "$CERT_DIR/privkey.pem"   "$EDITOR_CERTS_DIR/privkey.pem"
chmod 640 "$EDITOR_CERTS_DIR/privkey.pem"
ok "Certificates copied to $EDITOR_CERTS_DIR"

# Renewal hook
HOOK_DIR="/etc/letsencrypt/renewal-hooks/deploy"
mkdir -p "$HOOK_DIR"
HOOK_FILE="$HOOK_DIR/bbsfirewall-config-editor-reload.sh"
cat > "$HOOK_FILE" << HOOKEOF
#!/bin/bash
# Auto-generated by BBSFirewall setup-config-cert.sh
# Copies the renewed config-editor cert into BBSFirewall and restarts.
CERT_DIR="/etc/letsencrypt/live/bbsfirewall-config-editor"
cp "\$CERT_DIR/fullchain.pem" "$EDITOR_CERTS_DIR/fullchain.pem"
cp "\$CERT_DIR/privkey.pem"   "$EDITOR_CERTS_DIR/privkey.pem"
chmod 640 "$EDITOR_CERTS_DIR/privkey.pem"
HOOKEOF

if command -v pm2 &>/dev/null; then
  echo "pm2 restart $PM2_APP_NAME --silent" >> "$HOOK_FILE"
fi
chmod +x "$HOOK_FILE"
ok "Renewal hook installed at $HOOK_FILE"

echo ""
echo "  ======================================================"
echo "  Config editor certificate issued successfully!"
echo "  ======================================================"
echo ""
echo "  Add these lines to your .env:"
echo ""
echo -e "  ${GRN}CONFIG_EDITOR_ENABLED=true${NC}"
echo -e "  ${GRN}CONFIG_EDITOR_PORT=8443${NC}"
echo -e "  ${GRN}CONFIG_EDITOR_CERT_PATH=$EDITOR_CERTS_DIR/fullchain.pem${NC}"
echo -e "  ${GRN}CONFIG_EDITOR_KEY_PATH=$EDITOR_CERTS_DIR/privkey.pem${NC}"
echo ""
echo "  Also set CONFIG_EDITOR_USERNAME / CONFIG_EDITOR_PASSWORD and populate"
echo "  trustedhosts.txt with the IP(s) you will administer from."
echo ""
echo "  Then restart BBSFirewall:"
echo ""
echo "    pm2 restart $PM2_APP_NAME"
echo ""
echo "  Renewal is automatic via certbot's timer; the hook at"
echo "  $HOOK_FILE"
echo "  copies the new cert and restarts BBSFirewall."
echo ""
echo "  Manual renewal:"
echo "    bash $BBSFW_DIR/setup-config-cert.sh --renew"
echo ""
