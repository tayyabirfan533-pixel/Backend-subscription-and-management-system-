# Database ER diagram

```mermaid
erDiagram
    USERS ||--o{ ACTIVITY_LOGS : performs
    CUSTOMERS ||--o{ SUBSCRIPTIONS : owns
    PLANS ||--o{ SUBSCRIPTIONS : selected_for
    SUBSCRIPTIONS ||--o{ INVOICES : billed_by
    CUSTOMERS ||--o{ INVOICES : receives
    INVOICES ||--o{ PAYMENTS : has_attempts
    SUBSCRIPTIONS ||--o{ REMINDERS : triggers

    USERS {
      int id PK
      string name
      string email UK
      string password_hash
      string role
      bool is_active
      datetime created_at
    }
    CUSTOMERS {
      int id PK
      string name
      string email
      string company
      string phone
      datetime created_at
    }
    PLANS {
      int id PK
      string name UK
      string description
      int price_cents
      string billing_interval
      bool is_active
      datetime created_at
    }
    SUBSCRIPTIONS {
      int id PK
      int customer_id FK
      int plan_id FK
      string status
      date start_date
      date end_date
      datetime created_at
    }
    INVOICES {
      int id PK
      string invoice_number UK
      int subscription_id FK
      int customer_id FK
      date period_start
      date period_end
      int amount_cents
      string status
      datetime issued_at
      datetime due_at
    }
    PAYMENTS {
      int id PK
      string payment_ref UK
      string idempotency_key UK
      int invoice_id FK
      int amount_cents
      string status
      string method
      datetime created_at
    }
    ACTIVITY_LOGS {
      int id PK
      int actor_id FK
      string entity_type
      int entity_id
      string action
      string details
      datetime created_at
    }
    REMINDERS {
      int id PK
      int subscription_id FK
      date reminder_date
      string kind
      string message
      bool is_read
      datetime created_at
    }
```

## Important constraints

- User email is unique.
- Plan name is unique.
- Invoice number is unique.
- A subscription cannot have more than one invoice for the same `period_start`.
- Payment reference and non-null idempotency key are unique.
- Money is stored as integer cents to avoid floating-point rounding errors.
