import base64
import hashlib
import unittest
from datetime import datetime, time, timedelta
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from proteus import Model
from pywebpush import WebPushException
from trytond.config import config
from trytond.exceptions import UserError
from trytond.modules.company.tests.tools import create_company, get_company
from trytond.pool import Pool
from trytond.tests.test_tryton import DB_NAME, drop_db
from trytond.tests.tools import activate_modules
from trytond.transaction import Transaction


class TestNotifications(unittest.TestCase):

    def setUp(self):
        drop_db()
        super().setUp()
        if not config.has_section('cryptography'):
            config.add_section('cryptography')
        previous_key = config.get('cryptography', 'fernet_key')
        self.addCleanup(config.set, 'cryptography', 'fernet_key',
            previous_key or '')
        config.set('cryptography', 'fernet_key', Fernet.generate_key().decode())

    def tearDown(self):
        drop_db()
        super().tearDown()

    def test(self):
        activate_modules('notification_web_push')
        create_company()
        company = get_company()
        Application = Model.get('notification.web.application')
        Template = Model.get('notification.web.template')
        User = Model.get('web.user')
        ScheduledMessage = Model.get('notification.web.scheduled_message')
        application = Application(name='Customer App', code='test',
            company=company, origin='https://example.com', base_path='/app/')
        application.save()
        user = User(email='customer@example.com')
        user.save()
        other = User(email='other@example.com')
        other.save()
        template = Template(name='Promotion', category='promotion',
            title='Hello ${customer}', body='Offers from ${company}', path='offers')
        template.save()
        scheduled_message = ScheduledMessage(name='September', application=application,
            template=template, users=[user, other])
        scheduled_message.save()
        scheduled_message.click('schedule')
        self.assertEqual(scheduled_message.state, 'scheduled')
        with Transaction().start(DB_NAME, 0, _lock_tables=[
                'notification_web_scheduled_message', 'notification_web_delivery']) as transaction:
            pool = Pool()
            App = pool.get('notification.web.application')
            Preference = pool.get('notification.web.preference')
            Message = pool.get('notification.web.message')
            Subscription = pool.get('notification.web.subscription')
            Delivery = pool.get('notification.web.delivery')
            ScheduledMessageT = pool.get('notification.web.scheduled_message')
            UserT = pool.get('web.user')
            app = App(application.id)
            Preference.create([{'application': app.id, 'user': user.id,
                'promotion': True, 'reminder': False, 'service': True}])
            ScheduledMessageT.dispatch_due()
            messages = Message.search([('scheduled_message', '=', scheduled_message.id)])
            self.assertEqual(len(messages), 1)
            self.assertEqual(messages[0].user.id, user.id)
            ScheduledMessageT.dispatch_due()
            self.assertEqual(Message.search_count([
                ('scheduled_message', '=', scheduled_message.id)]), 1)
            self.assertIsNone(Message.publish(app, UserT(user.id),
                title='Cart', body='Checkout', category='reminder'))
            # Subscribe two devices and verify independent delivery outcomes.
            private_key = ec.generate_private_key(ec.SECP256R1())
            pem = private_key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption())
            key = private_key.public_key()
            key = key.public_bytes(serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint)
            p256dh = base64.urlsafe_b64encode(key).decode().rstrip('=')
            subscriptions = []
            for suffix in ('phone', 'desktop'):
                endpoint = 'https://fcm.googleapis.com/fcm/send/' + suffix
                subscriptions.extend(Subscription.create([{
                    'application': app.id, 'user': user.id, 'device': suffix,
                    'endpoint': endpoint,
                    'endpoint_hash': hashlib.sha256(endpoint.encode()).hexdigest(),
                    'p256dh': p256dh,
                    'auth': base64.urlsafe_b64encode(b'x' * 16).decode(),
                    }]))
            App.write([app], {'push_enabled': True,
                'private_key_file': pem, 'private_key_filename': 'private_key.pem',
                'public_key': p256dh, 'subject': 'mailto:admin@example.com'})
            self.assertEqual(bytes(app.private_key_file), pem)
            with transaction.set_context({
                    'notification.web.application.private_key_file': 'size'}):
                self.assertEqual(app.private_key().private_key.private_numbers(),
                    private_key.private_numbers())
            invalid_app = App(app.id)
            invalid_app.public_key = 'mismatched-key'
            with self.assertRaises(UserError):
                App.validate([invalid_app])
            for invalid_pem in [b'not a key',
                    private_key.public_key().public_bytes(
                        serialization.Encoding.PEM,
                        serialization.PublicFormat.SubjectPublicKeyInfo),
                    ec.generate_private_key(ec.SECP384R1()).private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption()),
                    private_key.private_bytes(serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.BestAvailableEncryption(b'test'))]:
                with self.assertRaises(UserError):
                    App(private_key_file=invalid_pem).private_key()
            message = Message.publish(app, UserT(user.id),
                title='Received', body='Your order is received')
            self.assertEqual(len(message.deliveries), 2)
            first, second = message.deliveries
            with patch('pywebpush.webpush', return_value=SimpleNamespace(
                    status_code=201)) as send:
                Delivery.send([first])
                Delivery.send([first])
                self.assertEqual(send.call_count, 1)
                self.assertEqual(send.call_args.kwargs[
                    'vapid_private_key'].private_key.private_numbers(),
                    private_key.private_numbers())
                self.assertIn('/app/notifications/', send.call_args.kwargs['data'])
            self.assertEqual(first.state, 'accepted')
            expired = SimpleNamespace(status_code=410)
            with patch('pywebpush.webpush', side_effect=WebPushException(
                    'expired', response=expired)):
                Delivery.send([second])
            self.assertEqual(second.state, 'failed')
            self.assertFalse(second.subscription.active)
            retry = Message.publish(app, UserT(user.id),
                title='Retry', body='Transient failure').deliveries[0]
            with patch('pywebpush.webpush', side_effect=WebPushException(
                    'unavailable', response=SimpleNamespace(status_code=503))):
                Delivery.send([retry])
            self.assertEqual(retry.state, 'pending')
            self.assertEqual(retry.attempts, 1)
            self.assertGreater(retry.next_attempt, datetime.now())
            # Revoking preferences between queueing and sending cancels push.
            pref, = Preference.search([('user', '=', user.id)])
            Preference.write([pref], {'service': False})
            Delivery.write([retry], {'next_attempt': datetime.now() - timedelta(seconds=1)})
            with patch('pywebpush.webpush') as send:
                Delivery.send([retry])
                send.assert_not_called()
            self.assertEqual(retry.state, 'cancelled')
            inbox_only = Message.publish(app, UserT(user.id),
                title='Inbox', body='Still saved without push')
            self.assertFalse(inbox_only.deliveries)
            transaction.commit()
        scheduled_message.reload()
        self.assertEqual(scheduled_message.state, 'sent')
        cancelled = ScheduledMessage(name='Cancelled', application=application,
            template=template, users=[User(user.id)])
        cancelled.save()
        cancelled.click('schedule')
        cancelled.click('cancel')
        self.assertEqual(cancelled.state, 'cancelled')
        copied, = ScheduledMessage.duplicate([cancelled])
        self.assertEqual(copied.state, 'draft')
        self.assertFalse(copied.messages)
        manual = ScheduledMessage(name='Manual service message', application=application,
            category='service', title='Manual', body='No template needed',
            scheduled_at=datetime.now() + timedelta(days=1), users=[User(other.id)])
        manual.save()
        manual.click('schedule')
        with Transaction().start(DB_NAME, 0,
                _lock_tables=['notification_web_scheduled_message']):
            pool = Pool()
            pool.get('notification.web.scheduled_message').dispatch_due()
            self.assertFalse(pool.get('notification.web.message').search([
                ('scheduled_message', '=', manual.id)]))


        daily = ScheduledMessage(name='Daily announcement', application=application,
            category='service', title='Daily', body='Hello', audience='all',
            frequency='daily', send_time=time(18), timezone='Europe/Madrid',
            scheduled_at=datetime.now() - timedelta(minutes=1))
        daily.save()
        daily.click('schedule')
        with Transaction().start(DB_NAME, 0,
                _lock_tables=['notification_web_scheduled_message']) as transaction:
            pool = Pool()
            ScheduledMessageT = pool.get('notification.web.scheduled_message')
            Message = pool.get('notification.web.message')
            ScheduledMessageT.dispatch_due()
            ScheduledMessageT.dispatch_due()
            self.assertEqual(Message.search_count([('scheduled_message', '=', daily.id)]), 2)
            rule = ScheduledMessageT(daily.id)
            self.assertEqual(rule.state, 'scheduled')
            self.assertGreater(rule.scheduled_at, datetime.now())
            self.assertEqual(rule.next_daily_send(datetime(2026, 3, 28, 18)),
                datetime(2026, 3, 29, 16))
            transaction.commit()
        daily.reload()
        daily.click('cancel')
        self.assertEqual(daily.state, 'cancelled')

        with Transaction().start(DB_NAME, 0):
            Subscription = Pool().get('notification.web.subscription')
            device = Subscription(subscriptions[0].id)
            cases = [
                ('Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 '
                    '(KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36',
                    'mobile', 'Android', 'Chrome Mobile', None),
                ('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
                    '(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
                    'desktop', 'Linux', 'Chrome', None),
                ('Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) '
                    'AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 '
                    'Mobile/15E148 Safari/604.1',
                    'mobile', 'iOS', 'Mobile Safari', 'iPhone'),
                ('Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) '
                    'AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 '
                    'Mobile/15E148 Safari/604.1',
                    'tablet', 'iOS', 'Mobile Safari', 'iPad'),
                ('Unrecognized client', 'unknown', None, None, None),
                ]
            for raw, kind, system, browser, model in cases:
                with self.subTest(user_agent=raw):
                    Subscription.write([device], {'device': raw})
                    self.assertEqual(device.device, raw)
                    self.assertEqual(device.device_type, kind)
                    self.assertEqual(device.operating_system, system)
                    self.assertEqual(device.browser, browser)
                    self.assertEqual(device.device_model, model)
            raw = cases[0][0]
            Subscription.write([device], {
                'device': raw, 'reported_device_model': 'Pixel 9'})
            self.assertEqual(device.device, raw)
            self.assertEqual(device.device_model, 'Pixel 9')

        with Transaction().start(DB_NAME, 0) as transaction:
            pool = Pool()
            ModelData = pool.get('ir.model.data')
            ModelAccess = pool.get('ir.model.access')
            FieldAccess = pool.get('ir.model.field.access')
            Menu = pool.get('ir.ui.menu')
            ResUser = pool.get('res.user')
            configuration_menu = ModelData.get_id(
                'notification_web_push', 'menu_configuration')
            configuration_models = [
                'notification.web.application', 'notification.web.template',
                'notification.web.scheduled_message',
                'notification.web.scheduled_message.user']
            for group_name, can_configure in [
                    ('group_notification', False),
                    ('group_notification_configuration', True)]:
                group_id = ModelData.get_id('notification_web_push', group_name)
                operator, = ResUser.create([{
                    'name': group_name, 'login': group_name,
                    'groups': [('add', [group_id])],
                    }])
                with transaction.set_user(operator.id), \
                        transaction.set_context(_check_access=True):
                    visible = Menu.search([('id', '=', configuration_menu)])
                    self.assertEqual(bool(visible), can_configure)
                    self.assertEqual(FieldAccess.check(
                        'notification.web.application',
                        ['private_key_file', 'private_key_filename'],
                        mode='read', raise_exception=False), can_configure)
                    access = ModelAccess.get_access(configuration_models)
                    for model in configuration_models:
                        self.assertTrue(access[model]['read'])
                        for mode in ('create', 'write', 'delete'):
                            self.assertEqual(bool(access[model][mode]),
                                can_configure, (group_name, model, mode))
                    for menu_name in ('application', 'template', 'campaign'):
                        menu_id = ModelData.get_id(
                            'notification_web_push', 'menu_' + menu_name)
                        self.assertEqual(bool(Menu.search([
                            ('id', '=', menu_id)])), can_configure)
                for menu_name in ('application', 'template', 'campaign'):
                    menu = Menu(ModelData.get_id(
                        'notification_web_push', 'menu_' + menu_name))
                    self.assertEqual(menu.parent.id, configuration_menu)
