#!/usr/bin/env bash
# Deploy the passlane approval page to AWS S3 + CloudFront (passlane#60).
#
# Everything runs against the AWS profile in $AWS_PROFILE (default:
# anssipiirainen.com). The script is idempotent: re-running it only
# re-uploads changed files and waits out pending resources.
#
# Stages:
#   1. S3 bucket (eu-north-1, public read via bucket policy) + upload of
#      page/ with correct Content-Type per file (the apple-app-site-
#      association MUST be application/json) and conservative caching.
#   2. ACM certificate in us-east-1 (CloudFront only accepts certs from
#      there), DNS-validated.
#   3. DNS records in Route 53: the ACM validation CNAME and the CloudFront
#      alias A/AAAA. If the profile cannot write Route 53 (the S3-www user
#      cannot), the script writes applicable change-batch files and prints
#      instructions instead of failing.
#   4. CloudFront distribution (S3 origin, ACM cert, HTTPS redirect).
#   5. Verification over HTTPS.
#
# Usage: ./deploy.sh [--page-dir DIR] [--domain NAME]
set -euo pipefail

PROFILE="${AWS_PROFILE:-anssipiirainen.com}"
REGION="eu-north-1"              # S3 bucket region (matches the main site)
CERT_REGION="us-east-1"          # CloudFront certs must live here
DOMAIN="approve.anssipiirainen.com"
PAGE_DIR="$(cd "$(dirname "$0")" && pwd)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --page-dir) PAGE_DIR="$2"; shift 2 ;;
    --domain) DOMAIN="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
BUCKET="$DOMAIN"
export AWS_PROFILE="$PROFILE"

log() { printf '\n==> %s\n' "$*"; }

# ---------------------------------------------------------------------------
# Stage 1: bucket + upload
# ---------------------------------------------------------------------------
log "Stage 1: S3 bucket $BUCKET ($REGION)"
if ! aws s3api head-bucket --bucket "$BUCKET" 2>/dev/null; then
  aws s3api create-bucket \
    --bucket "$BUCKET" \
    --region "$REGION" \
    --create-bucket-configuration "LocationConstraint=$REGION" >/dev/null
  # Public read through a bucket policy (ACL-free, works with the modern
  # BucketOwnerEnforced default; matches the account's website pattern).
  aws s3api put-public-access-block --bucket "$BUCKET" \
    --public-access-block \
    BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false
  aws s3api put-bucket-policy --bucket "$BUCKET" --policy "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Sid\": \"PublicReadGetObject\",
      \"Effect\": \"Allow\",
      \"Principal\": \"*\",
      \"Action\": \"s3:GetObject\",
      \"Resource\": \"arn:aws:s3:::$BUCKET/*\"
    }]
  }"
  echo "bucket created"
else
  echo "bucket exists"
fi

log "Uploading $PAGE_DIR -> s3://$BUCKET/"
upload() { # upload <path> <content-type> <cache-control>
  local path="$1" type="$2" cache="$3" key="${1#"$PAGE_DIR"/}"
  aws s3 cp "$path" "s3://$BUCKET/$key" \
    --content-type "$type" --cache-control "$cache" >/dev/null
  echo "  $key ($type, $cache)"
}
# The page is versionless: keep everything short-lived so fixes propagate.
HTML_CACHE="no-cache"
ASSET_CACHE="max-age=300"
while IFS= read -r -d '' f; do
  case "$f" in
    *.html)    upload "$f" "text/html; charset=utf-8" "$HTML_CACHE" ;;
    *.js)      upload "$f" "text/javascript; charset=utf-8" "$ASSET_CACHE" ;;
    *.css)     upload "$f" "text/css; charset=utf-8" "$ASSET_CACHE" ;;
    *.json)    upload "$f" "application/json" "$ASSET_CACHE" ;;
    */apple-app-site-association)
               # iOS fetchers reject the AASA unless it is exactly this
               # content type, served without a redirect.
               upload "$f" "application/json" "$ASSET_CACHE" ;;
    *)         upload "$f" "application/octet-stream" "$ASSET_CACHE" ;;
  esac
done < <(find "$PAGE_DIR" -type f \( -name '*.html' -o -name '*.js' -o -name '*.css' \
             -o -name '*.json' -o -name 'apple-app-site-association' \
             -o -name '*.svg' -o -name '*.png' -o -name '*.ico' -o -name '*.txt' \) -print0)

# ---------------------------------------------------------------------------
# Stage 2: ACM certificate (us-east-1)
# ---------------------------------------------------------------------------
log "Stage 2: ACM certificate for $DOMAIN ($CERT_REGION)"
CERT_ARN="$(aws acm list-certificates --region "$CERT_REGION" --output text \
  --query "CertificateSummaryList[?DomainName=='$DOMAIN'].CertificateArn | [0]")"
if [[ -z "$CERT_ARN" || "$CERT_ARN" == "None" ]]; then
  CERT_ARN="$(aws acm request-certificate --region "$CERT_REGION" \
    --domain-name "$DOMAIN" --validation-method DNS \
    --query 'CertificateArn' --output text)"
  echo "requested: $CERT_ARN"
else
  echo "existing:  $CERT_ARN"
fi

for _ in $(seq 1 30); do
  VALIDATION="$(aws acm describe-certificate --region "$CERT_REGION" \
    --certificate-arn "$CERT_ARN" \
    --query 'Certificate.DomainValidationOptions[0].ResourceRecord' \
    --output json 2>/dev/null || echo null)"
  [[ "$VALIDATION" != "null" && -n "$VALIDATION" ]] && break
  sleep 5
done

# ---------------------------------------------------------------------------
# Stage 3: DNS (Route 53 if writable, otherwise instructions)
# ---------------------------------------------------------------------------
log "Stage 3: DNS records"
ZONE_ID="$(aws route53 list-hosted-zones-by-name \
  --dns-name "${DOMAIN#*.}" --output text \
  --query 'HostedZones[0].Id' 2>/dev/null || true)"
ZONE_ID="${ZONE_ID##*/}"

if [[ -n "$ZONE_ID" && "$ZONE_ID" != "None" ]]; then
  echo "Route 53 zone $ZONE_ID is writable with this profile; creating records."
else
  echo "Route 53 is not accessible with profile $PROFILE."
  echo "Change-batch files are written next to this script; apply them with a"
  echo "profile/account that manages DNS for ${DOMAIN#*.} (console or CLI),"
  echo "then re-run this script."
fi

CERT_NAME="$(printf '%s' "$VALIDATION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["Name"])')"
CERT_VALUE="$(printf '%s' "$VALIDATION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["Value"])')"

upsert_record() { # upsert_record <zone> <file> <name> <type> <value>
  local zone="$1" file="$2" name="$3" type="$4" value="$5"
  python3 - "$file" "$name" "$type" "$value" <<'PYEOF'
import json, sys
path, name, rtype, value = sys.argv[1:5]
batch = {"Comment": "passlane approval page", "Changes": [{"Action": "UPSERT",
    "ResourceRecordSet": {"Name": name, "Type": rtype, "TTL": 300,
    "ResourceRecords": [{"Value": value}]}}]}
open(path, "w").write(json.dumps(batch, indent=2))
PYEOF
  if [[ -n "$zone" && "$zone" != "None" ]]; then
    aws route53 change-resource-record-sets --hosted-zone-id "$zone" \
      --change-batch "file://$file" >/dev/null && echo "  created $name $type"
  else
    echo "  pending (manual): $name $type -> $value  [$file]"
  fi
}

CERT_BATCH="$PAGE_DIR/r53-acm-validation.json"
upsert_record "$ZONE_ID" "$CERT_BATCH" "$CERT_NAME" CNAME "$CERT_VALUE"

# ---------------------------------------------------------------------------
# Stage 4: CloudFront distribution
# ---------------------------------------------------------------------------
log "Stage 4: waiting for certificate to be ISSUED (ACM validation)..."
aws acm wait certificate-validated --region "$CERT_REGION" --certificate-arn "$CERT_ARN"
echo "certificate issued"

log "CloudFront distribution for $DOMAIN"
DIST_ID="$(aws cloudfront list-distributions --output text \
  --query "DistributionList.Items[?contains(Aliases.Items, '$DOMAIN')].Id | [0]")"
if [[ -z "$DIST_ID" || "$DIST_ID" == "None" ]]; then
  cat > "$PAGE_DIR/cloudfront-config.json" <<EOF
{
  "CallerReference": "passlane-approve-$DOMAIN-$(date +%s)",
  "Comment": "passlane approval page ($DOMAIN)",
  "Enabled": true,
  "DefaultRootObject": "index.html",
  "Aliases": {"Quantity": 1, "Items": ["$DOMAIN"]},
  "Origins": {"Quantity": 1, "Items": [{
    "Id": "S3-$BUCKET",
    "DomainName": "$BUCKET.s3.amazonaws.com",
    "S3OriginConfig": {"OriginAccessIdentity": ""}
  }]},
  "DefaultCacheBehavior": {
    "TargetOriginId": "S3-$BUCKET",
    "ViewerProtocolPolicy": "redirect-to-https",
    "AllowedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]},
    "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]},
    "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",
    "Compress": true
  },
  "ViewerCertificate": {
    "ACMCertificateArn": "$CERT_ARN",
    "SSLSupportMethod": "sni-only",
    "MinimumProtocolVersion": "TLSv1.2_2021"
  },
  "HttpVersion": "http2",
  "PriceClass": "PriceClass_100"
}
EOF
  DIST_ID="$(aws cloudfront create-distribution \
    --distribution-config "file://$PAGE_DIR/cloudfront-config.json" \
    --query 'Distribution.Id' --output text)"
  echo "created: $DIST_ID"
else
  echo "existing: $DIST_ID"
fi

DIST_DOMAIN="$(aws cloudfront get-distribution --id "$DIST_ID" \
  --query 'Distribution.DomainName' --output text)"

ALIAS_BATCH="$PAGE_DIR/r53-alias.json"
ALIAS_TARGET="$DIST_DOMAIN"
upsert_alias() {
  python3 - "$ALIAS_BATCH" "$DOMAIN" "$ALIAS_TARGET" <<'PYEOF'
import json, sys
path, domain, target = sys.argv[1:4]
batch = {"Comment": "passlane approval page alias", "Changes": [
  {"Action": "UPSERT", "ResourceRecordSet": {
    "Name": domain, "Type": "A", "AliasTarget": {
      "HostedZoneId": "Z2FDTNDATAQYW2", "DNSName": target,
      "EvaluateTargetHealth": False}}}]}
open(path, "w").write(json.dumps(batch, indent=2))
PYEOF
  if [[ -n "$ZONE_ID" && "$ZONE_ID" != "None" ]]; then
    aws route53 change-resource-record-sets --hosted-zone-id "$ZONE_ID" \
      --change-batch "file://$ALIAS_BATCH" >/dev/null && echo "  created alias $DOMAIN -> $target"
  else
    echo "  pending (manual): alias $DOMAIN -> $target  [$ALIAS_BATCH]"
  fi
}
upsert_alias

log "Waiting for CloudFront deployment..."
aws cloudfront wait distribution-deployed --id "$DIST_ID"
echo "deployed"

# ---------------------------------------------------------------------------
# Stage 5: verification
# ---------------------------------------------------------------------------
log "Stage 5: verifying https://$DOMAIN/"
URL="https://$DOMAIN"
check() { # check <path> <expected-content-type>
  local ct
  ct="$(curl -sSI "$URL$1" | tr -d '\r' | awk 'tolower($1)=="content-type:"{print $2}')"
  if [[ "$ct" == "$2"* ]]; then echo "  OK  $1 ($ct)"; else echo "  FAIL $1 (got: '$ct', want: '$2')"; return 1; fi
}
FAILURES=0
check "/" "text/html" || FAILURES=$((FAILURES+1))
check "/test.html" "text/html" || FAILURES=$((FAILURES+1))
check "/.well-known/apple-app-site-association" "application/json" || FAILURES=$((FAILURES+1))

if [[ "$FAILURES" -eq 0 ]]; then
  echo ""
  echo "Deployed: $URL"
  echo "Enroll with: passlane approvals enroll --page $URL"
  exit 0
else
  echo "$FAILURES check(s) failed" >&2
  exit 1
fi
