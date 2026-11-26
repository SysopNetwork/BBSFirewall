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
  info "Renewing any certificates that are due..."
  bash "$BBSFW_DIR/cert-hooks.sh" refresh
  # Each certificate renews the way it was set up (webroot or standalone);
  # forcing --webroot here broke the standalone ones. The renewal hooks copy
  # each renewed cert in but skip their own restart, so BBSFirewall restarts
  # once at the end, and only if something was actually renewed.
  RENEWED_MARK="$(mktemp -u /tmp/bbsfw-renewed.XXXXXX)"
  RC=0
  BBSFW_SKIP_RESTART=1 certbot renew --no-random-sleep-on-renew \
    --deploy-hook "touch $RENEWED_MARK" || RC=$?

  if [[ -e "$RENEWED_MARK" ]]; then
    rm -f "$RENEWED_MARK"
    info "Restarting BBSFirewall to load the renewed certificates..."
    if command -v pm2 &>/dev/null; then
      pm2 restart "$PM2_APP_NAME" --silent
      ok "BBSFirewall restarted via pm2"
    else
      warn "pm2 not found â€” restart BBSFirewall manually to load the new cert"
    fi
  else
    info "Nothing was renewed, so no restart is needed."
  fi
  [[ "$RC" -eq 0 ]] || die "certbot reported a renewal failure (exit $RC) â€” see its output above"
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
# Passing --cert-name here makes certbot create a genuinely
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

# Renewal hook: copies each renewed cert in and restarts BBSFirewall. Written
# before certbot runs, because reissuing an existing certificate fires it.
bash "$BBSFW_DIR/cert-hooks.sh" install redirect
HOOK_FILE="/etc/letsencrypt/renewal-hooks/deploy/bbsfirewall-reload.sh"

CERT_DIR="/etc/letsencrypt/live/bbsfirewall-web-redirect"
# live/ links to the newest archive copy; if the link target is unchanged after
# certbot, it kept the existing certificate ("not yet due for renewal").
BEFORE="$(readlink -f "$CERT_DIR/fullchain.pem" 2>/dev/null || true)"

info "Running certbot..."
certbot "${CERTBOT_ARGS[@]}"

[[ -f "$CERT_DIR/fullchain.pem" ]] || die "Certificate not found at $CERT_DIR — certbot may have failed"
[[ -f "$CERT_DIR/privkey.pem"   ]] || die "Private key not found at $CERT_DIR — certbot may have failed"

EXPIRES="$(openssl x509 -noout -enddate -in "$CERT_DIR/fullchain.pem" 2>/dev/null | cut -d= -f2 || true)"
if [[ -n "$BEFORE" && "$BEFORE" == "$(readlink -f "$CERT_DIR/fullchain.pem")" ]]; then
  ISSUED=false
  ok "Existing certificate kept (expires ${EXPIRES:-unknown}). Certbot renews it within 30 days of expiry."
else
  ISSUED=true
  ok "Certificate issued to $CERT_DIR (expires ${EXPIRES:-unknown})"
fi

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
# Show the .env settings the sysop needs to add
# ---------------------------------------------------------------------------
echo ""
echo "  ======================================================"
if [[ "$ISSUED" == "true" ]]; then
  echo "  Certificate issued successfully!"
else
  echo "  Certificate is current. Nothing to renew yet."
fi
echo "  ======================================================"
echo ""
# The Tools tab sets BBSFW_SKIP_RESTART and loads the certificate itself (or
# says when a restart is needed), so the first-time setup steps don't apply.
if [[ -z "${BBSFW_SKIP_RESTART:-}" ]]; then
  echo "  If this is a new setup, add these lines to your .env to enable HTTPS redirect:"
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
fi
echo "  Renewal is automatic via certbot's built-in timer."
echo "  The renewal hook at $HOOK_FILE"
echo "  will copy the new cert and restart BBSFirewall for you."
echo ""
echo "  To renew manually at any time:"
echo "    bash $BBSFW_DIR/setup-certs.sh $DOMAIN --renew"
echo ""
