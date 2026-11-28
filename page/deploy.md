# Deploying the approval page (AWS S3 + CloudFront)

The canonical home of this page is
`https://approve.northernpeaks.dev` (passlane#84) — the domain the CLI
defaults to and the iOS app accepts by default, so they agree with no
overrides. The first deployment lives on at
`https://approve.anssipiirainen.com`: page enrollment against it keeps
working (`--page` / `$PASSLANE_APPROVAL_PAGE`), and it stays deployed
until the canonical domain is live and users have re-enrolled.

Both are S3 for the bytes, CloudFront for HTTPS and the domain, and an
ACM certificate (us-east-1) validated through Route 53, where the
zone lives. The same script deploys either domain.

| Deployment | Command | State |
| ---------- | ------- | ----- |
| `approve.northernpeaks.dev` (canonical) | `AWS_PROFILE=anssi-admin ./deploy.sh` | **Runbook, not yet provisioned** — see below |
| `approve.anssipiirainen.com` (first) | `./deploy.sh --domain approve.anssipiirainen.com` | Live; repeat deploys work with the default profile |

## One-time / every deploy

```sh
cd page
./deploy.sh                                  # canonical domain
./deploy.sh --domain approve.anssipiirainen.com   # the first deployment
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

1. creates the `<domain>` bucket in `eu-north-1` (public read via
   bucket policy — the account's established website pattern; re-ensured
   on every run) and uploads the page with per-type `Content-Type` (the
   `apple-app-site-association` **must** be `application/json`) and
   conservative cache headers (`no-cache` for HTML, `max-age=300` for
   assets — the page is versionless). All S3 calls go through the
   **regional endpoint** — the global one can 307-redirect fresh
   regional buckets, and CloudFront passes origin redirects through to
   viewers;
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

## Provisioning `approve.northernpeaks.dev` — runbook state

The domain was purchased (Northern Peaks Development); everything below
is what stands between that and the canonical domain serving the page.
The infra/DNS run itself is manual — with the capable profile, from
inside `page/`:

```sh
AWS_PROFILE=anssi-admin ./deploy.sh
```

In order, that run expects:

1. **The `northernpeaks.dev` Route 53 zone to exist** (a public hosted
   zone in the same AWS account), with the registrar pointing at its
   nameservers. Without the zone the script still provisions bucket,
   certificate and distribution, and degrades the DNS records to the
   manual `r53-*.json` batches — applied with whichever credentials
   manage the domain.
2. First provisioning, per the two-profile callout above: ACM
   certificate `approve.northernpeaks.dev` (DNS-validated through the
   zone), the S3 bucket, the CloudFront distribution and its alias
   records.
3. Verify `https://approve.northernpeaks.dev/test.html` (desktop and
   iOS Safari), and the `apple-app-site-association` content type —
   stage 5 checks it, and universal links (the app's `pair.html` /
   `approve.html` entry points) depend on it.
4. After that, repeat content deploys are `./deploy.sh` with the default
   profile — the same one-command flow as the first deployment has
   today.

What remains after the run: nothing in this repo — the CLI already
defaults to the domain, and the app's accept-list switch is tracked in
the passlane-ios repo. Until the run happens, default links
(`pair.html`, `approve.html`) point at a domain that does not answer
yet; the deployed page stays reachable at `approve.anssipiirainen.com`
via `--page`.

## After deploying

- open `https://<domain>/test.html` on desktop and on iOS Safari — the
  in-browser protocol self-test must pass;
- enroll from the Mac:

  ```sh
  passlane approvals enroll --page https://approve.anssipiirainen.com
  ```

  (or export `PASSLANE_APPROVAL_PAGE`) — the domain is pinned into the
  enrollment, which is why it must be decided **before** the first
  enroll. Pairing the iOS app needs no page deployment, but its links
  ride the same domain.
