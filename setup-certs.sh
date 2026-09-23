#!/bin/bash
#
# BBSFirewall - Let's Encrypt certificate setup
# https://github.com/SysopNetwork/BBSFirewall
#
# Gets a free TLS certificate from Let's Encrypt using certbot's webroot method.
# BBSFirewall's HTTP redirect server stays running the whole time — no downtime.
#
# Usage:
#   bash setup-certs.sh yourdomain.com
#   bash setup-certs.sh yourdomain.com --email you@example.com
#   bash setup-certs.sh yourdomain.com --renew
#
# Requirements:
#   - BBSFirewall must be running with WEB_REDIRECT_ENABLED=true
#   - Port 80 must be reachable from the internet (Let's Encrypt needs it)
#   - Run as root or with sudo
#   - Domain DNS must already point to this server
#

set -euo pipefail

# ---------------------------------------------------------------------------
# Config — change these if you moved things around
# ---------------------------------------------------------------------------
BBSFW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="$BBSFW_DIR/certs"
WEBROOT="$CERTS_DIR/webroot"
PM2_APP_NAME="bbsfirewall"  # matches the pm2 process name (pm2 list)

# ---------------------------------------------------------------------------
# Helpers
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
# Parse arguments
# ---------------------------------------------------------------------------
DOMAIN=""
EMAIL=""
RENEW=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --email) EMAIL="$2"; shift 2 ;;
    --renew) RENEW=true; shift ;;
    -*) die "Unknown option: $1" ;;
    *)  DOMAIN="$1"; shift ;;
  esac
done

# ---------------------------------------------------------------------------
# Sanity checks
# ---------------------------------------------------------------------------
echo ""
echo "  BBSFirewall - Let's Encrypt Certificate Setup"
echo "  =============================================="
echo ""

[[ "$(id -u)" -eq 0 ]] || die "This script must be run as root. Try: sudo bash setup-certs.sh $DOMAIN"

if [[ "$RENEW" == "false" ]]; then
  [[ -n "$DOMAIN" ]] || die "No domain specified. Usage: bash setup-certs.sh yourdomain.com"
fi

# ---------------------------------------------------------------------------
# Install certbot if it's not already there
# ---------------------------------------------------------------------------
if ! command -v certbot &>/dev/null; then
  info "certbot not found — installing..."

  if command -v apt-get &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq certbot
  elif command -v yum &>/dev/null; then
    yum install -y certbot
  elif command -v dnf &>/dev/null; then
    dnf install -y certbot
  else
    die "Could not install certbot automatically. Install it manually: https://certbot.eff.org"
  fi

  ok "certbot installed"
else
  ok "certbot is already installed ($(certbot --version 2>&1 | head -1))"
fi

# ---------------------------------------------------------------------------
# Renewal mode — just renew all existing certs and restart
# ---------------------------------------------------------------------------
if [[ "$RENEW" == "true" ]]; then
  info "Renewing all certificates..."
  certbot renew --webroot --webroot-path "$WEBROOT" --quiet

  info "Restarting BBSFirewall to load new certificates..."
  if command -v pm2 &>/dev/null; then
    pm2 restart "$PM2_APP_NAME" --silent
    ok "BBSFirewall restarted via PM2"
  else
    warn "PM2 not found — restart BBSFirewall manually to load the new cert"
  fi

  ok "Renewal complete"
  exit 0
fi

# ---------------------------------------------------------------------------
# Fresh cert issuance
# ---------------------------------------------------------------------------
info "Domain: $DOMAIN"
info "Webroot: $WEBROOT"

# Create webroot directory — certbot needs it to exist before it starts
mkdir -p "$WEBROOT/.well-known/acme-challenge"
ok "ACME webroot ready"

# Check that BBSFirewall's HTTP server is actually serving the webroot.
# If port 80 isn't listening we'll warn but continue — maybe the sysop knows
# what they're doing and port 80 is handled elsewhere.
if command -v ss &>/dev/null; then
  if ! ss -tlnp | grep -q ':80 '; then
    warn "Nothing appears to be listening on port 80."
    warn "BBSFirewall's HTTP redirect server must be running for webroot verification."
    warn "Make sure WEB_REDIRECT_ENABLED=true in your .env and restart BBSFirewall first."
    echo ""
    read -rp "  Continue anyway? [y/N] " confirm
    [[ "${confirm,,}" == "y" ]] || exit 1
  fi
fi

# Build the certbot command
#
# --cert-name is deliberately fixed (not left to default to $DOMAIN) for the
# same reason setup-config-cert.sh uses a fixed --cert-name
# "bbsfirewall-config-editor": the web redirect and the config editor are
# very commonly issued for the SAME hostname (one physical box). Without an
# explicit --cert-name here, certbot's own domain-based duplicate-avoidance
# recognizes that domain is already covered by the config editor's lineage
# and treats the request as a no-op renewal check ("Certificate not yet due
# for renewal; no action taken") — exiting 0 without ever creating
# /etc/letsencrypt/live/$DOMAIN, which then made THIS script's own
# post-check below fail with a misleading "certbot may have failed" (the
# domains can be identical; it's the lineage NAME that must differ).
# Confirmed live: passing --cert-name here makes certbot create a genuinely
# independent lineage regardless of any domain overlap with another one.
CERTBOT_ARGS=(
  certonly
  --webroot
  --webroot-path "$WEBROOT"
  --domain "$DOMAIN"
  --agree-tos
  --non-interactive
  --cert-name "bbsfirewall-web-redirect"
)

# Email is optional but highly recommended — it gets you expiry warnings
if [[ -n "$EMAIL" ]]; then
  CERTBOT_ARGS+=(--email "$EMAIL")
else
  warn "No email address provided. You won't get expiry warning emails."
  warn "Consider re-running with: --email you@example.com"
  CERTBOT_ARGS+=(--register-unsafely-without-email)
fi

info "Running certbot..."
certbot "${CERTBOT_ARGS[@]}"

CERT_DIR="/etc/letsencrypt/live/bbsfirewall-web-redirect"

[[ -f "$CERT_DIR/fullchain.pem" ]] || die "Certificate not found at $CERT_DIR — certbot may have failed"
[[ -f "$CERT_DIR/privkey.pem"   ]] || die "Private key not found at $CERT_DIR — certbot may have failed"

ok "Certificate issued to $CERT_DIR"

# ---------------------------------------------------------------------------
# Copy certs into the BBSFirewall certs directory
# We copy (not symlink) so BBSFirewall can read them without root privileges.
# A renewal hook below keeps the copies up to date automatically.
# ---------------------------------------------------------------------------
mkdir -p "$CERTS_DIR"
cp "$CERT_DIR/fullchain.pem" "$CERTS_DIR/fullchain.pem"
cp "$CERT_DIR/privkey.pem"   "$CERTS_DIR/privkey.pem"
chmod 640 "$CERTS_DIR/privkey.pem"
ok "Certificates copied to $CERTS_DIR"

# ---------------------------------------------------------------------------
# Install a certbot renewal hook that copies the new certs and restarts
# BBSFirewall automatically whenever certbot renews (which it does via its own
# systemd timer or cron job — you don't have to think about it).
# ---------------------------------------------------------------------------
HOOK_DIR="/etc/letsencrypt/renewal-hooks/deploy"
mkdir -p "$HOOK_DIR"

HOOK_FILE="$HOOK_DIR/bbsfirewall-reload.sh"
cat > "$HOOK_FILE" << HOOKEOF
#!/bin/bash
# Auto-generated by BBSFirewall setup-certs.sh
# Copies renewed Let's Encrypt certs into BBSFirewall and restarts.
BBSFW_DIR="$BBSFW_DIR"
CERT_DIR="/etc/letsencrypt/live/bbsfirewall-web-redirect"
cp "\$CERT_DIR/fullchain.pem" "\$BBSFW_DIR/certs/fullchain.pem"
cp "\$CERT_DIR/privkey.pem"   "\$BBSFW_DIR/certs/privkey.pem"
chmod 640 "\$BBSFW_DIR/certs/privkey.pem"
HOOKEOF

# Append the PM2 restart if PM2 is available
if command -v pm2 &>/dev/null; then
  cat >> "$HOOK_FILE" << HOOKEOF
pm2 restart $PM2_APP_NAME --silent
HOOKEOF
fi

chmod +x "$HOOK_FILE"
ok "Renewal hook installed at $HOOK_FILE"

# ---------------------------------------------------------------------------
# Show the .env settings the sysop needs to add
# ---------------------------------------------------------------------------
echo ""
echo "  ======================================================"
echo "  Certificate issued successfully!"
echo "  ======================================================"
echo ""
echo "  Add these lines to your .env file to enable HTTPS redirect:"
echo ""
echo -e "  ${GRN}HTTPS_REDIRECT_ENABLED=true${NC}"
echo -e "  ${GRN}HTTPS_REDIRECT_PORT=443${NC}"
echo -e "  ${GRN}HTTPS_CERT_PATH=$CERTS_DIR/fullchain.pem${NC}"
echo -e "  ${GRN}HTTPS_KEY_PATH=$CERTS_DIR/privkey.pem${NC}"
echo ""
echo "  Then restart BBSFirewall:"
echo ""
echo "    pm2 restart $PM2_APP_NAME"
echo ""
echo "  Renewal is automatic via certbot's built-in timer."
echo "  The renewal hook at $HOOK_FILE"
echo "  will copy the new cert and restart BBSFirewall for you."
echo ""
echo "  To renew manually at any time:"
echo "    bash $BBSFW_DIR/setup-certs.sh $DOMAIN --renew"
echo ""
