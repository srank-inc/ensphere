# Checklist Index

Last updated: 2026-06-07

Framework checklists are agent-facing prompts for technology-specific review.
They are copied into `cli/internal/checklist/data/` by `make checklists` and
embedded in the CLI by `make build`.

| Checklist | File | Typical Use |
|-----------|------|-------------|
| AWS IAM | [aws-iam.md](aws-iam.md) | AWS identity and privilege review |
| AWS S3 | [aws-s3.md](aws-s3.md) | S3 bucket, object, policy, logging review |
| Cloudflare R2 | [cloudflare-r2.md](cloudflare-r2.md) | R2 bucket and access control review |
| Django | [django.md](django.md) | Python/Django application review |
| Express.js | [express-js.md](express-js.md) | Node/Express application review |
| FastAPI | [fastapi.md](fastapi.md) | Python/FastAPI application review |
| Kubernetes Pod Security | [k8s-pod-security.md](k8s-pod-security.md) | Kubernetes workload and pod security review |
| Laravel | [laravel.md](laravel.md) | PHP/Laravel application review |
| Next.js App Router | [nextjs-app-router.md](nextjs-app-router.md) | Next.js app and route handler review |
| Rails | [rails.md](rails.md) | Ruby on Rails application review |
| Spring Boot | [spring-boot.md](spring-boot.md) | Java/Spring Boot application review |
| Supabase RLS | [supabase-rls.md](supabase-rls.md) | Supabase row-level security review |
| tRPC | [trpc.md](trpc.md) | tRPC router and procedure review |

## Update Rule

After editing any checklist, run:

```bash
make checklists
make verify-generated
```
