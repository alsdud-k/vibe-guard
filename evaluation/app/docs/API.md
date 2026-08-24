# vibeguard-test-app API

## Authentication

All protected endpoints require a Bearer JWT token.

```
Authorization: Bearer <token>
```

## Endpoints

### Public
- `GET /health` — Health check
- `GET /public/` — Welcome message
- `GET /public/status` — Status

### Users (requires user auth)
- `GET /users/me` — My profile
- `PUT /users/me` — Update profile
- `GET /users/me/orders` — My orders

### Admin (requires admin role)
- `GET /admin/dashboard` — Dashboard
- `GET /admin/users` — List users
- `DELETE /admin/users/{id}` — Delete user
- `GET /admin/settings` — Settings
- `PUT /admin/settings` — Update settings
- `GET /admin/logs` — Audit logs
- `POST /admin/announcements` — Create announcement
- `DELETE /admin/announcements/{id}` — Delete announcement

### Products (requires admin role)
- `GET /products/` — List products
- `POST /products/` — Create product
- `PUT /products/{id}` — Update product
- `DELETE /products/{id}` — Delete product
