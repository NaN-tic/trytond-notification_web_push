import base64
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from string import Template as TextTemplate
from urllib.parse import urlsplit

import requests
from user_agents import parse as parse_user_agent
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from py_vapid import Vapid

from trytond.config import config
from trytond.exceptions import UserError
from trytond.i18n import gettext
from trytond.model import (
    DeactivableMixin, Index, ModelSQL, ModelView, Unique, Workflow, fields)
from trytond.pool import Pool, PoolMeta
from trytond.pyson import Eval
from trytond.transaction import Transaction


CATEGORIES = [
    ('service', 'Orders and Service'),
    ('promotion', 'Promotions'),
    ('reminder', 'Cart Reminders'),
    ]
EDITABLE = {'readonly': Eval('state') != 'draft'}


def local_path(value):
    """Only app-relative paths; never allow links outside the application."""
    value = value or ''
    parsed = urlsplit(value)
    if (parsed.scheme or parsed.netloc or value.startswith('/')
            or '\\' in value or '%' in parsed.path
            or any(part == '..' for part in parsed.path.split('/'))
            or any(ord(char) < 32 for char in value)):
        raise UserError('Use a relative application path, e.g. sales?checkout=1.')
    return value


def validate_endpoint(endpoint):
    # Endpoints come from an untrusted browser. Restrict network destinations.
    parsed = urlsplit(endpoint)
    hosts = config.get('web_push', 'allowed_hosts', default=(
        'fcm.googleapis.com,updates.push.services.mozilla.com,'
        'web.push.apple.com')).split(',')
    hostname = parsed.hostname or ''
    allowed = hostname in {host.strip() for host in hosts}
    allowed |= hostname.endswith('.push.apple.com')
    if (parsed.scheme != 'https' or not allowed or parsed.username
            or parsed.password or parsed.port not in (None, 443)
            or parsed.fragment):
        raise UserError('Invalid push service endpoint.')


def validate_subscription_keys(p256dh, auth):
    try:
        public = base64.urlsafe_b64decode(p256dh + '===')
        secret = base64.urlsafe_b64decode(auth + '===')
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public)
        if len(secret) != 16:
            raise ValueError
    except (ValueError, TypeError):
        raise UserError('Invalid push subscription keys.') from None


class PushSession(requests.Session):
    def request(self, *args, **kwargs):
        kwargs['allow_redirects'] = False
        return super().request(*args, **kwargs)


class Application(DeactivableMixin, ModelSQL, ModelView):
    'Web Push Application'
    __name__ = 'notification.web.application'

    name = fields.Char('Name', required=True)
    code = fields.Char('Code', required=True)
    company = fields.Many2One('company.company', 'Company', required=True)
    origin = fields.Char('HTTPS Origin', required=True)
    base_path = fields.Char('Application Path', required=True)
    public_key = fields.Char('VAPID Public Key')
    encrypted_private_key = fields.Binary('Encrypted VAPID Private Key')
    private_key_file = fields.Function(fields.Binary('VAPID Private Key',
        filename='private_key_filename',
        help='Upload the unencrypted PEM file for the VAPID private key.'),
        'get_private_key_file', 'set_private_key_file')
    private_key_filename = fields.Char('Private Key Filename')
    subject = fields.Char('VAPID Contact',
        help='Contact URI, for example mailto:admin@example.com.')
    push_enabled = fields.Boolean('Enable Push Sending')

    @classmethod
    def __register__(cls, module_name):
        super().__register__(module_name)
        handler = cls.__table_handler__(module_name)
        if handler.column_exist('private_key_file'):
            table = cls.__table__()
            cursor = Transaction().connection.cursor()
            cursor.execute(*table.select(table.id, table.private_key_file))
            for record_id, key_file in cursor.fetchall():
                if key_file:
                    encrypted = cls.get_fernet().encrypt(bytes(key_file))
                    cursor.execute(*table.update(
                        [table.encrypted_private_key], [encrypted],
                        where=table.id == record_id))
            handler.drop_column('private_key_file')

    @classmethod
    def get_fernet(cls):
        key = config.get('cryptography', 'fernet_key')
        try:
            if not key:
                raise ValueError
            return Fernet(key)
        except (ValueError, TypeError):
            raise UserError(gettext(
                'notification_web_push.msg_vapid_encryption_key')) from None

    def get_private_key_file(self, name):
        with Transaction().set_context({
                'notification.web.application.encrypted_private_key': None}):
            application = self.__class__(self.id)
            encrypted = application.encrypted_private_key
        value = None
        if encrypted:
            try:
                value = self.get_fernet().decrypt(bytes(encrypted))
            except InvalidToken:
                raise UserError(gettext(
                    'notification_web_push.msg_vapid_decryption')) from None
        if Transaction().context.get(f'{self.__name__}.{name}') == 'size':
            return len(value) if value else 0
        return value

    @classmethod
    def set_private_key_file(cls, applications, name, value):
        encrypted = cls.get_fernet().encrypt(bytes(value)) if value else None
        cls.write(applications, {'encrypted_private_key': encrypted})

    @staticmethod
    def default_base_path():
        return '/'

    @staticmethod
    def default_company():
        return Transaction().context.get('company')

    @classmethod
    def __setup__(cls):
        super().__setup__()
        table = cls.__table__()
        cls._sql_constraints.append((
            'code_unique', Unique(table, table.code),
            'notification_web_push.msg_unique'))

    @classmethod
    def validate(cls, records):
        super().validate(records)
        for record in records:
            parsed = urlsplit(record.origin)
            if (parsed.scheme != 'https' or not parsed.hostname
                    or parsed.path not in ('', '/') or parsed.query
                    or parsed.fragment or parsed.username or parsed.password):
                raise UserError('The application origin must be an HTTPS origin.')
            if not re.fullmatch(r'[a-z][a-z0-9_]*', record.code):
                raise UserError('Use a lowercase application code with underscores.')
            if (not record.base_path.startswith('/')
                    or not record.base_path.endswith('/')):
                raise UserError('The application path must start and end with /.')
            local_path(record.base_path[1:])
            if urlsplit(record.base_path).query or urlsplit(record.base_path).fragment:
                raise UserError('The application path cannot contain a query or fragment.')
            if record.private_key_file:
                vapid = record.private_key()
                public_key = base64.urlsafe_b64encode(
                    vapid.public_key.public_bytes(
                        serialization.Encoding.X962,
                        serialization.PublicFormat.UncompressedPoint)
                    ).decode().rstrip('=')
                if (record.public_key
                        and record.public_key.rstrip('=') != public_key):
                    raise UserError(gettext(
                        'notification_web_push.msg_vapid_key_mismatch'))
            if record.push_enabled and not (
                    record.public_key and record.subject
                    and record.private_key()):
                raise UserError('Configure the public/private VAPID keys and contact.')

    def private_key(self):
        with Transaction().set_context({
                'notification.web.application.private_key_file': None}):
            application = (self.__class__(self.id)
                if self.id is not None and self.id >= 0 else self)
            key_file = application.private_key_file
        if key_file:
            try:
                key = serialization.load_pem_private_key(
                    bytes(key_file), password=None)
            except (ValueError, TypeError, UnsupportedAlgorithm):
                raise UserError(gettext(
                    'notification_web_push.msg_invalid_vapid_private_key')) from None
            if (not isinstance(key, ec.EllipticCurvePrivateKey)
                    or not isinstance(key.curve, ec.SECP256R1)):
                raise UserError(gettext(
                    'notification_web_push.msg_invalid_vapid_private_key'))
            return Vapid(private_key=key)
        return None

    def url(self, path=''):
        return self.origin.rstrip('/') + self.base_path + local_path(path)

    def eligible_user(self, user):
        return user.active


class Template(DeactivableMixin, ModelSQL, ModelView):
    'Notification Template'
    __name__ = 'notification.web.template'

    name = fields.Char('Name', required=True)
    category = fields.Selection(CATEGORIES, 'Category', required=True)
    title = fields.Char('Title', required=True, size=120)
    body = fields.Text('Message', required=True,
        help='Placeholders: ${customer}, ${company}, ${reference}. Plain text.')
    path = fields.Char('Application Link',
        help='Relative to the application, e.g. sales. Leave blank for home.')

    @staticmethod
    def default_category():
        return 'service'

    @classmethod
    def validate(cls, records):
        super().validate(records)
        for record in records:
            local_path(record.path)
            for value in (record.title, record.body):
                try:
                    TextTemplate(value).substitute(
                        customer='', company='', reference='')
                except (ValueError, KeyError):
                    raise UserError('Invalid notification placeholder.') from None

    def content(self, user, application, reference=''):
        values = {
            'customer': user.party.rec_name if user.party else user.email,
            'company': application.company.rec_name,
            'reference': reference,
            }
        return {
            'title': TextTemplate(self.title).substitute(values)[:120],
            'body': TextTemplate(self.body).substitute(values)[:1000],
            'path': self.path or '', 'category': self.category,
            }


class Preference(ModelSQL, ModelView):
    'Notification Preferences'
    __name__ = 'notification.web.preference'

    application = fields.Many2One('notification.web.application',
        'Application', required=True, ondelete='CASCADE')
    user = fields.Many2One('web.user', 'User', required=True, ondelete='CASCADE')
    service = fields.Boolean('Order and Service Push')
    promotion = fields.Boolean('Promotions')
    reminder = fields.Boolean('Cart Reminders')
    changed_at = fields.DateTime('Changed At', readonly=True)

    @staticmethod
    def default_service():
        return True

    @classmethod
    def __setup__(cls):
        super().__setup__()
        table = cls.__table__()
        cls._sql_constraints.append((
            'user_application_unique', Unique(table, table.user, table.application),
            'notification_web_push.msg_unique'))

    @classmethod
    def allows(cls, application, user, category):
        preferences = cls.search([
            ('application', '=', application.id), ('user', '=', user.id)], limit=1)
        return (getattr(preferences[0], category) if preferences
            else category == 'service')


class Subscription(DeactivableMixin, ModelSQL, ModelView):
    'Push Device Subscription'
    __name__ = 'notification.web.subscription'
    _rec_name = 'device'

    application = fields.Many2One('notification.web.application',
        'Application', required=True, ondelete='CASCADE')
    user = fields.Many2One('web.user', 'User', required=True, ondelete='CASCADE')
    device = fields.Char('Device', required=True)
    device_type = fields.Function(fields.Selection([
        ('unknown', 'Unknown'), ('mobile', 'Mobile'),
        ('tablet', 'Tablet'), ('desktop', 'Computer')],
        'Device Type'), 'get_device_information')
    operating_system = fields.Function(fields.Char('Operating System'),
        'get_device_information')
    browser = fields.Function(fields.Char('Browser'), 'get_device_information')
    device_model = fields.Function(fields.Char('Device Model'),
        'get_device_information')
    reported_device_model = fields.Char('Browser-Reported Device Model',
        size=200, readonly=True)
    endpoint = fields.Char('Endpoint', required=True)
    endpoint_hash = fields.Char('Endpoint Hash', required=True, readonly=True)
    p256dh = fields.Char('Public Key', required=True)
    auth = fields.Char('Authentication Secret', required=True)

    @classmethod
    def get_device_information(cls, records, names):
        result = {name: {} for name in names}
        for record in records:
            agent = parse_user_agent(record.device or '')
            device_type = 'unknown'
            if agent.is_tablet:
                device_type = 'tablet'
            elif agent.is_mobile:
                device_type = 'mobile'
            elif agent.is_pc:
                device_type = 'desktop'
            model = record.reported_device_model or agent.device.model
            if model in ('K', 'Other', 'Generic Smartphone', 'Smartphone',
                    'Android'):
                model = None
            values = {
                'device_type': device_type,
                'operating_system': (agent.os.family
                    if agent.os.family != 'Other' else None),
                'browser': (agent.browser.family
                    if agent.browser.family != 'Other' else None),
                'device_model': model or None,
                }
            for name in names:
                result[name][record.id] = values[name]
        return result

    @classmethod
    def __setup__(cls):
        super().__setup__()
        table = cls.__table__()
        cls._sql_constraints.append((
            'endpoint_unique', Unique(table, table.endpoint_hash),
            'notification_web_push.msg_unique'))

    @classmethod
    def validate(cls, records):
        super().validate(records)
        for record in records:
            validate_endpoint(record.endpoint)
            if record.endpoint_hash != hashlib.sha256(
                    record.endpoint.encode()).hexdigest():
                raise UserError('Invalid subscription fingerprint.')
            validate_subscription_keys(record.p256dh, record.auth)


class ScheduledMessage(Workflow, ModelSQL, ModelView):
    'Scheduled Message'
    __name__ = 'notification.web.scheduled_message'

    name = fields.Char('Name', required=True, states=EDITABLE)
    application = fields.Many2One('notification.web.application', 'Application',
        required=True, states=EDITABLE)
    template = fields.Many2One('notification.web.template', 'Template',
        states=EDITABLE)
    category = fields.Selection(CATEGORIES, 'Category', required=True, states=EDITABLE)
    title = fields.Char('Title', required=True, size=120, states=EDITABLE)
    body = fields.Text('Message', required=True, states=EDITABLE,
        help='Plain text. Placeholders: ${customer}, ${company}, ${reference}.')
    path = fields.Char('Application Link', states=EDITABLE)
    users = fields.Many2Many('notification.web.scheduled_message.user',
        'scheduled_message', 'user', 'Recipients', states={
            'readonly': Eval('state') != 'draft',
            'invisible': Eval('audience') == 'all'})
    scheduled_at = fields.DateTime('Next Send At', states=EDITABLE)
    frequency = fields.Selection([('once', 'Once'), ('daily', 'Daily')],
        'Frequency', required=True, states=EDITABLE)
    send_time = fields.Time('Local Sending Time', states={
        'readonly': Eval('state') != 'draft',
        'invisible': Eval('frequency') != 'daily'})
    timezone = fields.Char('Time Zone', required=True, states=EDITABLE,
        help='IANA time zone, for example Europe/Madrid.')
    audience = fields.Selection([('selected', 'Selected Recipients'),
        ('all', 'All Application Customers')], 'Audience', required=True,
        states=EDITABLE)
    message_type = fields.Selection([('message', 'Message'),
        ('promotion', 'Promotion')], 'Message Type', required=True, states=EDITABLE)

    test_user = fields.Many2One('web.user', 'Test Recipient', states=EDITABLE)
    messages = fields.One2Many('notification.web.message', 'scheduled_message',
        'Messages', readonly=True)
    state = fields.Selection([
        ('draft', 'Draft'), ('scheduled', 'Scheduled'),
        ('sent', 'Dispatched'), ('cancelled', 'Cancelled')],
        'State', required=True, readonly=True)

    @staticmethod
    def default_frequency():
        return 'once'

    @staticmethod
    def default_timezone():
        return 'Europe/Madrid'

    @staticmethod
    def default_audience():
        return 'selected'

    @staticmethod
    def default_message_type():
        return 'message'

    @fields.depends('message_type')
    def on_change_message_type(self):
        if self.message_type == 'promotion':
            self.category = 'promotion'

    def next_daily_send(self, now):
        zone = ZoneInfo(self.timezone)
        local = now.replace(tzinfo=timezone.utc).astimezone(zone)
        target = datetime.combine(local.date(), self.send_time, tzinfo=zone)
        if target <= local:
            target = datetime.combine(local.date() + timedelta(days=1),
                self.send_time, tzinfo=zone)
        return target.astimezone(timezone.utc).replace(tzinfo=None)

    def recipient_users(self):
        users = (Pool().get('web.user').search([])
            if self.audience == 'all' else self.users)
        return [user for user in users if self.application.eligible_user(user)]

    def publish_messages(self):
        Message = Pool().get('notification.web.message')
        for user in self.recipient_users():
            Message.publish(self.application, user, scheduled_message=self,
                **self.content(user))

    @staticmethod
    def default_state():
        return 'draft'

    @staticmethod
    def default_category():
        return 'service'

    @fields.depends('template')
    def on_change_template(self):
        if self.template:
            self.category = self.template.category
            self.title = self.template.title
            self.body = self.template.body
            self.path = self.template.path

    @classmethod
    def validate(cls, records):
        super().validate(records)
        for record in records:
            local_path(record.path)
            try:
                ZoneInfo(record.timezone)
            except (ZoneInfoNotFoundError, ValueError):
                raise UserError('Select a valid IANA time zone.') from None
            if record.frequency == 'daily' and not record.send_time:
                raise UserError('Set the sending time for daily messages.')
            if record.message_type == 'promotion' and record.category != 'promotion':
                raise UserError('Promotions must use the promotions category.')
            for value in (record.title, record.body):
                try:
                    TextTemplate(value).substitute(customer='', company='', reference='')
                except (ValueError, KeyError):
                    raise UserError('Invalid notification placeholder.') from None

    @classmethod
    def write(cls, *args):
        for records, values in zip(args[::2], args[1::2]):
            allowed = {'state'}
            if Transaction().context.get('_notification_dispatch'):
                allowed.add('scheduled_at')
            if set(values) - allowed and any(r.state != 'draft' for r in records):
                raise UserError('Scheduled messages cannot be edited. Cancel and copy instead.')
        super().write(*args)

    @classmethod
    def copy(cls, records, default=None):
        default = dict(default or {})
        default.update(state='draft', scheduled_at=None, messages=None)
        return super().copy(records, default=default)

    def content(self, user):
        values = {
            'customer': user.party.rec_name if user.party else user.email,
            'company': self.application.company.rec_name, 'reference': ''}
        return {'category': self.category,
            'title': TextTemplate(self.title).substitute(values)[:120],
            'body': TextTemplate(self.body).substitute(values)[:1000],
            'path': self.path or ''}

    @classmethod
    def __setup__(cls):
        super().__setup__()
        table = cls.__table__()
        cls._sql_indexes.add(Index(table,
            (table.state, Index.Equality()), (table.scheduled_at, Index.Range())))
        cls._transitions |= {
            ('draft', 'scheduled'), ('scheduled', 'cancelled'),
            ('draft', 'cancelled'), ('scheduled', 'sent')}
        cls._buttons.update({
            'open_messages': {},
            'schedule': {'invisible': Eval('state') != 'draft'},
            'cancel': {'invisible': ~Eval('state').in_(['draft', 'scheduled'])},
            'send_test': {'invisible': Eval('state') != 'draft'},
            })

    @classmethod
    @ModelView.button_action('notification_web_push.act_message')
    def open_messages(cls, records):
        return {'pyson_domain': json.dumps([
            ('scheduled_message', 'in', [record.id for record in records])])}

    @classmethod
    @ModelView.button
    @Workflow.transition('scheduled')
    def schedule(cls, records):
        for record in records:
            if (record.audience == 'selected' and not record.users) or not record.application.active:
                raise UserError('Select recipients and an active application.')
            if any(not record.application.eligible_user(u) for u in record.users):
                raise UserError('A recipient does not belong to this application.')
            if record.template and not record.template.active:
                raise UserError('Select an active template.')
            if not record.scheduled_at:
                cls.write([record], {'scheduled_at': (record.next_daily_send(datetime.now())
                    if record.frequency == 'daily' else datetime.now())})

    @classmethod
    @ModelView.button
    @Workflow.transition('cancelled')
    def cancel(cls, records):
        pass

    @classmethod
    @ModelView.button
    def send_test(cls, records):
        Message = Pool().get('notification.web.message')
        for record in records:
            if not record.test_user or not record.application.eligible_user(
                    record.test_user):
                raise UserError('Select an eligible test recipient.')
            with Transaction().set_user(0):
                Message.publish(record.application, record.test_user,
                    scheduled_message=record, **record.content(record.test_user))

    @classmethod
    def dispatch_due(cls):
        cls.lock()
        scheduled_messages = cls.search([
            ('state', '=', 'scheduled'), ('scheduled_at', '<=', datetime.now()),
            ('application.active', '=', True)], limit=20)
        for scheduled_message in scheduled_messages:
            scheduled_message.publish_messages()
            if scheduled_message.frequency == 'daily':
                with Transaction().set_context(_notification_dispatch=True):
                    cls.write([scheduled_message], {
                        'scheduled_at': scheduled_message.next_daily_send(
                            datetime.now())})
            else:
                cls.write([scheduled_message], {'state': 'sent'})


class ScheduledMessageUser(ModelSQL):
    'Scheduled Message Recipient'
    __name__ = 'notification.web.scheduled_message.user'
    scheduled_message = fields.Many2One('notification.web.scheduled_message',
        'Scheduled Message', required=True, ondelete='CASCADE')
    user = fields.Many2One('web.user', 'User', required=True, ondelete='CASCADE')


class Message(ModelSQL, ModelView):
    'Customer Inbox Message'
    __name__ = 'notification.web.message'
    _rec_name = 'title'

    application = fields.Many2One('notification.web.application', 'Application',
        required=True, ondelete='CASCADE')
    user = fields.Many2One('web.user', 'Recipient', required=True, ondelete='CASCADE')
    scheduled_message = fields.Many2One('notification.web.scheduled_message',
        'Scheduled Message', ondelete='SET NULL')
    category = fields.Selection(CATEGORIES, 'Category', required=True)
    title = fields.Char('Title', required=True, size=120)
    body = fields.Text('Message', required=True)
    path = fields.Char('Application Link')
    read_at = fields.DateTime('Read At', readonly=True)
    expires_at = fields.DateTime('Push Expires At', required=True)
    deliveries = fields.One2Many('notification.web.delivery', 'message',
        'Push Deliveries', readonly=True)

    @classmethod
    def __setup__(cls):
        super().__setup__()
        cls._order = [('id', 'DESC')]
        table = cls.__table__()
        cls._sql_indexes.add(Index(table,
            (table.application, Index.Equality()), (table.user, Index.Equality()),
            (table.read_at, Index.Range())))

    @classmethod
    def publish(cls, application, user, title, body, category='service',
            path='', scheduled_message=None, **extra):
        pool = Pool()
        Preference = pool.get('notification.web.preference')
        Subscription = pool.get('notification.web.subscription')
        Delivery = pool.get('notification.web.delivery')
        if not application.active or not application.eligible_user(user):
            return
        allowed = Preference.allows(application, user, category)
        # Service messages always remain in the inbox. Marketing is opt-in.
        if category != 'service' and not allowed:
            return
        local_path(path)
        message, = cls.create([dict(
            application=application.id, user=user.id,
            title=title[:120], body=body[:1000], category=category, path=path,
            scheduled_message=scheduled_message.id if scheduled_message else None,
            expires_at=datetime.now() + timedelta(days=2), **extra)])
        if allowed and application.push_enabled:
            subscriptions = Subscription.search([
                ('application', '=', application.id), ('user', '=', user.id)])
            if subscriptions:
                Delivery.create([{'message': message.id,
                    'subscription': subscription.id} for subscription in subscriptions])
        return message

    def can_deliver(self):
        return (self.application.active and self.application.eligible_user(self.user)
            and self.expires_at > datetime.now()
            and Pool().get('notification.web.preference').allows(
                self.application, self.user, self.category))


class Delivery(ModelSQL, ModelView):
    'Push Delivery'
    __name__ = 'notification.web.delivery'

    message = fields.Many2One('notification.web.message', 'Message',
        required=True, ondelete='CASCADE')
    subscription = fields.Many2One('notification.web.subscription', 'Device',
        required=True, ondelete='CASCADE')
    state = fields.Selection([
        ('pending', 'Pending'), ('accepted', 'Accepted by Push Service'),
        ('failed', 'Failed'), ('cancelled', 'Cancelled')],
        'State', required=True, readonly=True)
    attempts = fields.Integer('Attempts', required=True, readonly=True)
    next_attempt = fields.DateTime('Next Attempt', required=True, readonly=True)
    accepted_at = fields.DateTime('Accepted At', readonly=True)
    error = fields.Char('Error', readonly=True)

    @classmethod
    def __setup__(cls):
        super().__setup__()
        table = cls.__table__()
        cls._sql_indexes.add(Index(table,
            (table.state, Index.Equality()), (table.next_attempt, Index.Range())))

    @staticmethod
    def default_state():
        return 'pending'

    @staticmethod
    def default_attempts():
        return 0

    @staticmethod
    def default_next_attempt():
        return datetime.now()

    @classmethod
    def enqueue_due(cls):
        # Called by cron: workers process committed outbox records, one per task.
        for delivery in cls.search([
                ('state', '=', 'pending'),
                ('message.application.push_enabled', '=', True),
                ('next_attempt', '<=', datetime.now())], limit=100):
            cls.__queue__.send([delivery])

    @classmethod
    def send(cls, deliveries):
        from pywebpush import WebPushException, webpush
        cls.lock(deliveries)
        for delivery in deliveries:
            if (delivery.state != 'pending'
                    or delivery.next_attempt > datetime.now()):
                continue
            message = delivery.message
            subscription = delivery.subscription
            application = message.application
            if (not subscription.active or subscription.user != message.user
                    or subscription.application != application
                    or not message.can_deliver()):
                cls.write([delivery], {'state': 'cancelled'})
                continue
            if not application.push_enabled:
                continue
            attempts = delivery.attempts + 1
            values = {'attempts': attempts}
            status = None
            try:
                validate_endpoint(subscription.endpoint)
                with PushSession() as session:
                    result = webpush(
                        subscription_info={
                            'endpoint': subscription.endpoint,
                            'keys': {'p256dh': subscription.p256dh,
                                'auth': subscription.auth}},
                        data=json.dumps({
                            'title': message.title, 'body': message.body,
                            'url': application.url(
                                'notifications/' + str(message.id)),
                            'tag': 'notification-' + str(message.id)}),
                        vapid_private_key=application.private_key(),
                        vapid_claims={'sub': application.subject},
                        ttl=max(0, int((message.expires_at - datetime.now()).total_seconds())),
                        timeout=10, requests_session=session)
                    status = result.status_code
            except WebPushException as exc:
                if exc.response is not None:
                    status = exc.response.status_code
            except (requests.RequestException, ValueError, UserError):
                pass
            if status is not None and 200 <= status < 300:
                values.update(state='accepted', accepted_at=datetime.now(), error=None)
            elif status in (404, 410):
                Pool().get('notification.web.subscription').write(
                    [subscription], {'active': False})
                values.update(state='failed', error='Subscription expired')
            else:
                values['error'] = ('HTTP %s' % status if status else
                    'Push service or configuration error')
                if attempts >= 5 or (status is not None
                        and status < 500 and status not in (408, 429)):
                    values['state'] = 'failed'
                else:
                    values['next_attempt'] = datetime.now() + timedelta(
                        minutes=min(60, 2 ** attempts))
            cls.write([delivery], values)


class Cron(metaclass=PoolMeta):
    __name__ = 'ir.cron'

    @classmethod
    def __setup__(cls):
        super().__setup__()
        cls.method.selection.extend([
            ('notification.web.scheduled_message|dispatch_due',
                'Dispatch Scheduled Web Messages'),
            ('notification.web.delivery|enqueue_due', 'Send Web Push Notifications'),
            ])
