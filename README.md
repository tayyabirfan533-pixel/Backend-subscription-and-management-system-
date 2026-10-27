# Subscription & Billing Management System

A backend-only Subscription & Billing Management API built with FastAPI, SQLAlchemy, and SQLite. It is designed as a 2-day internship task demo; payments are simulated and no real payment provider is connected. No frontend is included.

## Features

- JWT-style bearer authentication with Admin and Staff roles.
- Customer directory with search and editing.
- Monthly/yearly plans; admin-only plan creation and editing.
- Subscription lifecycle: Pending, Active, Cancelled, Expired; activate, renew, cancel, upgrade/downgrade, remaining days.
- Unique invoice references and one invoice per subscription billing period; invoice totals are stored in integer cents.
- Simulated payment success/failure, transaction history, and idempotency-key support.
- Printable invoice HTML endpoint for invoice rendering.
- Dashboard analytics: customers, active subscriptions, current-month paid revenue, pending invoices, revenue trend and subscription growth.
- Hourly background maintenance: expire ended subscriptions and create one renewal reminder per subscription period.
- Activity log and reminders endpoints.
- Single Render web service serves the API only; interactive API testing is available through Swagger UI at `/docs`.

## Tech stack

- Python 3.11+ (Python 3.13 is supported)
- FastAPI + Uvicorn
- SQLAlchemy 2.x
- SQLite by default; can use a PostgreSQL `DATABASE_URL` supported by SQLAlchemy if a PostgreSQL driver is added.
- Pydantic v2

## Run locally

### 1. Create environment and install dependencies

Windows PowerShell:

```powershell
py -3.13 -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

### 2. Configure environment variables

Set these before starting the server. Change the demo password and use a long random secret outside local development.

Windows PowerShell:

```powershell
$env:SECRET_KEY = "replace-with-a-long-random-secret"
$env:ADMIN_EMAIL = "admin@example.com"
$env:ADMIN_PASSWORD = "ChangeMe123!"
```

macOS/Linux:

```bash
export SECRET_KEY='replace-with-a-long-random-secret'
export ADMIN_EMAIL='admin@example.com'
export ADMIN_PASSWORD='ChangeMe123!'
```

If omitted locally, the demo defaults are `admin@example.com` / `ChangeMe123!`. Do not keep the demo password in production. The first application startup creates the admin and three example plans if they do not already exist.

### 3. Start the API

```bash
uvicorn app.main:app --reload
```

- API root: <http://127.0.0.1:8000/>
- Swagger API docs: <http://127.0.0.1:8000/docs>
- Health check: <http://127.0.0.1:8000/health>

## Demo workflow (API-only)

1. Sign in using `POST /auth/login` and copy the bearer token from the response.
2. Use **Authorize** in Swagger UI (`/docs`) and enter the token as `Bearer <token>`.
3. Create a customer with `POST /customers`.
4. List available plans with `GET /plans`.
5. Create a subscription with `POST /subscriptions`; a Pending subscription and invoice are created together.
6. Simulate a payment through the payment endpoint. A successful payment marks the invoice Paid and activates a Pending subscription.
7. Review subscriptions, invoices, payment history, reminders, activity, and analytics through their API endpoints.
8. Use activate, renew, cancel, or change-plan endpoints to demonstrate the subscription lifecycle.

## API overview

Authentication:
- `POST /auth/login`
- `GET /auth/me`
- `POST /staff` (Admin only)
- `GET /staff` (Admin only)

Customers:
- `POST /customers`
- `GET /customers?search=...&limit=100&offset=0`
- `GET /customers/{customer_id}`
- `PUT /customers/{customer_id}`

Plans:
- `GET /plans`
- `POST /plans` (Admin only)
- `PUT /plans/{plan_id}` (Admin only)

Subscriptions:
- `POST /subscriptions`
- `GET /subscriptions?subscription_status=Active&search=...&plan_id=...&customer_id=...`
- `POST /subscriptions/{id}/activate`
- `POST /subscriptions/{id}/renew`
- `POST /subscriptions/{id}/cancel`
- `POST /subscriptions/{id}/change-plan`

Invoices and payments:
- `GET /invoices?invoice_status=Pending&search=...`
- `GET /invoices/{id}`
- `GET /invoices/{id}/print`
- `POST /invoices/{id}/simulate-payment` (send `Idempotency-Key` header to protect retries)
- `GET /payments?payment_status=Paid`

Operations:
- `GET /analytics`
- `GET /reminders?unread_only=true`
- `POST /reminders/{id}/read`
- `GET /activity?limit=100`
- `POST /admin/run-maintenance` (Admin only)

All routes except `/`, `/health`, and `/auth/login` require `Authorization: Bearer <token>` unless noted otherwise. Use Swagger's **Authorize** button and enter the token.

## Render deployment

1. Push this folder to a GitHub repository.
2. In Render, choose **New + → Blueprint** and select the repository containing `render.yaml`, or create a Web Service manually.
3. For manual service configuration use:
   - Runtime: Python 3
   - Build command: `pip install -r requirements.txt`
   - Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
4. Set `ADMIN_PASSWORD` to a strong secret in Render's environment settings. Keep the generated `SECRET_KEY`; set a new value if needed.
5. After deploy, check `/health`, `/docs`, and `/` on the Render URL.

### Storage note

The default SQLite database is suitable for a demo only. A Render free instance's local filesystem may be ephemeral, so records can be lost after redeploy/restart. For persistent production use, configure PostgreSQL and a suitable database driver, and back up data. The hourly maintenance task runs inside the web process; multiple web instances would each run it, so production deployments should move this job to a single dedicated worker or external scheduler.

## Database schema

See [`docs/ERD.md`](docs/ERD.md).

## Security and scope notes

- This project simulates payments only. It does not charge real cards or store payment card data.
- Change `SECRET_KEY` and `ADMIN_PASSWORD` before deployment.
- Use HTTPS in production and consider rate limiting, audit retention, email delivery for reminders, and database migrations before real use.
- Currency is represented in USD in the demo UI; adjust currency display and plan values for your requirements.
- Plan changes update the current pending invoice when it is unpaid; if the current period is already paid, the new plan is billed for the next period. For production billing, define proration and invoice adjustment rules explicitly.
