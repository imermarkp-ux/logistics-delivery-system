# Logistics & Delivery Tracking System

A Flask + SQLite starter application with admin, rider, and customer roles.

## Features
- Login and customer self-registration
- Admin dashboard, user management, shipment creation, rider assignment
- Rider dashboard and shipment status updates
- Customer shipment list and public tracking-number lookup
- Shipment status timeline/history
- Basic reports and shipment counts
- Password hashing and role-based access checks

## Run locally (Windows / VS Code)

1. Install Python 3.10 or newer.
2. Open this folder in VS Code.
3. Open Terminal and run:

```powershell
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

4. Open http://127.0.0.1:5000

## First admin account
- Email: `admin@logistics.local`
- Password: `admin123`

Log in and immediately create your own admin account from **Users**. For a real deployment, change the default password and set a strong `SECRET_KEY` environment variable. Do not use the development settings as-is on a public production server.

## Create test accounts
- Customers can register using the Register page.
- Admin can create rider and additional admin accounts under Users.
- Admin creates shipments and assigns riders.

## Important notes
- Tracking lookup is public, so it only displays basic shipment details and status history. Avoid entering sensitive personal information into notes or public-facing fields.
- This is a functional local starter project, not a production-certified courier platform. Before real deployment, add CSRF protection, rate limiting, email/SMS notifications, backups, audit logging, and stronger production configuration.
- SQLite database `logistics.db` is created automatically on first run.
