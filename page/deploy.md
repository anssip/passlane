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
`anssipiirainen.com` (override with `AWS_PROFILE`) for everything that
profile can do, and:

> **Two profiles, two situations.** The `anssipiirainen.com` profile
> (IAM user `S3-www`) can manage S3 and read CloudFront/ACM, but it
> **cannot request certificates, write Route 53 records, or create
> distributions**.
>
> - **First provisioning on a new domain** — run with a profile that has
>   those rights, e.g. `AWS_PROFILE=anssi-admin ./deploy.sh`. This
>   requests the ACM certificate, writes the DNS records, and creates the
>   CloudFront distribution.
> - **Repeat deploys (content updates)** — `./deploy.sh` with the default
>   profile is enough: the certificate and distribution already exist, so
>   the run re-uploads files and verifies. (DNS-record write failures
>   degrade to the printed manual batches rather than aborting.)
>
> If a run is interrupted before the certificate is issued or the
> distribution exists, finish it with the capable profile; do not delete
> the half-provisioned resources — every stage resumes.

The script:

1. creates the `approve.anssipiirainen.com` bucket in `eu-north-1` (public
   read via bucket policy — the account's established website pattern;
   re-ensured on every run) and uploads the page with per-type
   `Content-Type` (the `apple-app-site-association` **must** be
   `application/json`) and conservative cache headers (`no-cache` for
   HTML, `max-age=300` for assets — the page is versionless). All S3
   calls go through the **regional endpoint** — the global one can
   307-redirect fresh regional buckets, and CloudFront passes origin
   redirects through to viewers;
2. requests/reuses the ACM certificate in `us-east-1` (CloudFront only
   accepts certs from there);
3. writes the DNS records — **if the profile can write Route 53**, it
   upserts them; if the zone is visible but a write is refused (or the
   zone is not visible at all), it writes `r53-acm-validation.json` and
   `r53-alias.json` next to the script and prints them, and you apply
   them with whatever credentials manage DNS for the zone. From inside
   `page/`:
   ```sh
   aws --profile <dns-profile> route53 change-resource-record-sets \
     --hosted-zone-id <ZONE_ID> --change-batch file://r53-acm-validation.json
   # after the certificate is ISSUED and the distribution exists:
   aws --profile <dns-profile> route53 change-resource-record-sets \
     --hosted-zone-id <ZONE_ID> --change-batch file://r53-alias.json
   ```
4. creates/reuses the CloudFront distribution (S3 origin on the regional
   endpoint, HTTPS redirect, ACM cert, `index.html` root) and waits for
   deployment;
5. verifies the live URLs require HTTP 200 with no redirect and the
   expected MIME — including `apple-app-site-association`.

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
