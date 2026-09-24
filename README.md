# Web Push notifications for Tryton 7.8

Reusable module for web-user inboxes, manual communications, scheduled messages,
plain-text templates, per-category preferences and Web Push delivery. Depends on
`web_user` and `company`; application-specific integrations belong in separate
modules.

## Installation

Install this module alongside your other Tryton modules and install its Python
requirements in the server environment:

```sh
pip install -r requirements.txt
```

These versions were verified with cryptography 50.0.1 and pyOpenSSL 26.4.0.
py-vapid 1.9.4 requires cryptography >= 46; upgrade older pyOpenSSL installations
alongside it. Earlier py-vapid releases may fail to generate VAPID keys with
`TypeError: curve must be an EllipticCurve instance`.
Update the module list and activate `notification_web_push` (or
upgrade a module that depends on it). Run the Tryton cron service. For larger
scheduled messages also run a Tryton queue worker and configure `[queue] worker = True`.

Two scheduled actions are installed: dispatch scheduled messages and enqueue push
notifications, both every minute. Sending takes place in separate queue tasks,
after the transaction that stores the inbox message has committed. HTTP calls
never occur while confirming an order.

## Configure an application

Administrators configure applications under **Notifications → Configuration → Applications**:
company, name, lowercase code, public HTTPS origin and application path (leading
and trailing slash). For example `https://orders.example.com` and `/`.

Generate a persistent VAPID key pair in a protected directory using the `vapid`
command from py-vapid:

```sh
umask 077
vapid --gen
vapid --applicationServerKey
```

Copy the printed application server key into the application's **VAPID Public
Key** and upload `private_key.pem` in **VAPID Private Key** from the Tryton client.
The uploaded key must be an unencrypted PEM P-256 private key matching the public
key. Only configuration users and administrators can access the uploaded file.
The key is stored encrypted with Fernet in the application database, using the
same `[cryptography] fernet_key` setting as `certificate_manager`. Configure the
same master key on HTTP, cron and worker servers and back it up separately from
the database. No per-application private key path is used. Missing or invalid
master keys prevent uploading or using private keys; an incorrect master key
cannot decrypt existing keys. Changing the master key requires re-encrypting
existing keys, including certificates using that key.

Updating the module encrypts previously uploaded plaintext keys and removes the
old plaintext column. The master key must be configured before this update.
Older backups may still contain plaintext keys. Authorized configuration users
and administrators can still download the decrypted PEM from Tryton.

Set **VAPID Contact** to a contact URI, e.g. `mailto:admin@example.com`, and enable
push sending. HTTP, cron and worker processes use the key stored in the database.
When upgrading from server configuration, upload the same existing key file:
existing subscriptions depend on this key pair.

The public browser-facing API belongs to the integrating application. It must
validate authentication and CSRF, associate devices with the actual authenticated
user, and restrict inbox/preference changes to that user. The integrating module
supplies these endpoints. Endpoints to push providers are HTTPS-only and restricted to
FCM, Mozilla and Apple. Additional trusted hosts may be configured in
`[web_push] allowed_hosts` (comma-separated exact hosts). Redirects are disabled.

## Send and manage messages

Assign the **Notifications** group to operators to consult notifications and
delivery history for their allowed companies. Assign **Notifications -
Configuration** to users who manage applications, templates and scheduled
messages under **Notifications → Configuration**. This group inherits the
general notification access and is assigned to the administrator by default.

Create a scheduled message, select an application and recipients, and enter title/body.
Optionally choose a template to copy its content, then adjust it. Supported
placeholders are `${customer}`, `${company}` and `${reference}` (empty for manual
scheduled messages). Templates use string substitution, never Python expressions or HTML.
Links are relative to the application, e.g. `sales`; absolute/external URLs and
parent-path traversal are rejected.

Use **Send Test** for a selected test recipient (their normal preferences apply).
Use **Schedule / Send** with a future date to schedule or leave the date empty to
send on the next cron run. Scheduled content/recipients cannot be edited: cancel
and copy the scheduled message to change them. Cancellation is possible before dispatch.

* Order/service messages always remain in the inbox. Their push channel can be
  disabled independently.
* Promotions and cart reminders require opt-in and are omitted when disabled.
* A push subscription is per application, user and device. It does not opt the
  user into promotions or reminders.
* Preferences are checked again when sending. Revoked, expired, reassigned and
  inactive-user subscriptions are skipped. 404/410 deactivate devices; temporary
  failures retry up to five attempts with backoff. Push expires after two days.
* “Accepted by Push Service” is not proof of display or reading. `read_at` records
  the app's explicit read action. The inbox remains available without push.

The outbox prevents normal duplicate dispatch and rechecks already accepted
records. As with other external side effects, a crash after provider acceptance
but before database commit may cause a retry. A stable notification tag replaces
repeated visible notifications for the same message.

## Integration API

Within the business transaction call the pool model's `publish` method:

```python
Message = Pool().get('notification.web.message')
Message.publish(application, web_user, title='Order received',
    body='Your order has been received.', path='orders/123', category='service')
```

Use a trusted server context. Extend `Application.eligible_user` to enforce
application-specific recipient membership and `Message.can_deliver` for business
conditions that must still hold at send time. The browser must implement service
worker registration, opt-in subscription, notification display and click handling.

## Verification

From the monorepository root, use the test-workflow runner with module
`notification_web_push` and scenario `notifications`. The scenario uses Proteus,
an isolated database, real subscription-key validation and mocked external push
responses. It never sends messages to real devices.

## Scheduled messages

The Scheduled Messages screen supports a single send (Next Send At) or a daily
send at a local time and IANA time zone. Daily rules remain scheduled, advancing
the next execution atomically with publication. A delayed cron sends one batch,
then advances to the next future occurrence without replaying missed days.
Recipients may be selected explicitly or resolved from all eligible application
users at dispatch time. Promotions continue to require opt-in.

The Devices screen preserves the original user-agent string and derives the
device type, operating system, browser and available device model from it,
including for existing subscriptions. Unknown models remain empty. Integrating
applications may provide `reported_device_model` when the browser exposes its
model through User-Agent Client Hints; this takes precedence over the parsed
model. Device information is descriptive and must not be used for authorization.

Business modules extend the message type selection and `publish_messages` for
conditional audiences; scheduling and delivery remain reusable infrastructure.
