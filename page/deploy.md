# Deploying the approval page (AWS S3 + CloudFront)

The production home of this page is
`https://approve.anssipiirainen.com` — S3 for the bytes, CloudFront for
HTTPS and the domain, an ACM certificate (us-east-1) validated through
Route 53, where the `anssipiirainen.com` zone lives.

## One-time / every deploy

```sh
cd page
./deploy.sh
```

The script is idempotent. It uses the AWS CLI profile named
`anssipiirainen.com` (override with `AWS_PROFILE`), and:

1. creates the `approve.anssipiirainen.com` bucket in `eu-north-1` (public
   read via bucket policy — the account's established website pattern) and
   uploads the page with per-type `Content-Type` (the
   `apple-app-site-association` **must** be `application/json`) and
   conservative cache headers (`no-cache` for HTML, `max-age=300` for
   assets — the page is versionless);
2. requests/reuses the ACM certificate in `us-east-1` (CloudFront only
   accepts certs from there);
3. writes the DNS records — **if the profile can write Route 53**, it
   upserts them; otherwise it writes `r53-acm-validation.json` and
   `r53-alias.json` next to the script and prints them, and you apply
   them with whatever credentials manage DNS for the zone:
   ```sh
   aws --profile <dns-profile> route53 change-resource-record-sets \
     --hosted-zone-id <ZONE_ID> --change-batch file://page/r53-acm-validation.json
   # after the certificate is ISSUED and the distribution exists:
   aws --profile <dns-profile> route53 change-resource-record-sets \
     --hosted-zone-id <ZONE_ID> --change-batch file://page/r53-alias.json
   ```
4. creates/reuses the CloudFront distribution (S3 origin, HTTPS redirect,
   ACM cert, `index.html` root) and waits for deployment;
5. verifies the live URLs, including the `apple-app-site-association`
   content type.

The two `r53-*.json` and `cloudfront-config.json` files are generated at
run time — do not commit them.

## After deploying

- open `https://approve.anssipiirainen.com/test.html` on desktop and on
  iOS Safari — the in-browser protocol self-test must pass;
- enroll from the Mac:

  ```sh
  passlane approvals enroll --page https://approve.anssipiirainen.com
  ```

  (or export `PASSLANE_APPROVAL_PAGE`) — the domain is pinned into the
  enrollment, which is why it must be decided **before** the first enroll.
