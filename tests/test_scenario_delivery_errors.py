import base64
import hashlib
import unittest
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import patch

import requests
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


class TestDeliveryErrors(unittest.TestCase):

    def setUp(self):
        drop_db()
        super().setUp()

    def tearDown(self):
        drop_db()
        super().tearDown()

    def test(self):
        activate_modules('notification_web_push')
        create_company()
        if not config.has_section('cryptography'):
            config.add_section('cryptography')
        previous_key = config.get('cryptography', 'fernet_key')
        self.addCleanup(config.set, 'cryptography', 'fernet_key',
            previous_key or '')
        config.set('cryptography', 'fernet_key', Fernet.generate_key().decode())
        Application = Model.get('notification.web.application')
        User = Model.get('web.user')
        application = Application(name='Error diagnostics', code='errors',
            company=get_company(), origin='https://example.com', base_path='/')
        application.save()
        user = User(email='diagnostics@example.com')
        user.save()
        with Transaction().start(DB_NAME, 0,
                _lock_tables=['notification_web_delivery']):
            pool = Pool()
            App = pool.get('notification.web.application')
            Message = pool.get('notification.web.message')
            Subscription = pool.get('notification.web.subscription')
            Delivery = pool.get('notification.web.delivery')
            UserT = pool.get('web.user')
            app = App(application.id)
            key = ec.generate_private_key(ec.SECP256R1())
            public = base64.urlsafe_b64encode(key.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint)).decode().rstrip('=')
            App.write([app], {
                'private_key_file': key.private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()),
                'public_key': public, 'subject': 'mailto:admin@example.com',
                'push_enabled': True})
            endpoint = 'https://fcm.googleapis.com/fcm/send/secret-device-token'
            Subscription.create([{
                'application': app.id, 'user': user.id, 'device': 'Test browser',
                'endpoint': endpoint,
                'endpoint_hash': hashlib.sha256(endpoint.encode()).hexdigest(),
                'p256dh': public,
                'auth': base64.urlsafe_b64encode(b'x' * 16).decode(),
                }])
            for exception, expected in [
                    (requests.exceptions.SSLError(endpoint), 'TLS certificate'),
                    (requests.Timeout(endpoint), 'timed out'),
                    (requests.ConnectionError(endpoint), 'DNS'),
                    (requests.RequestException(endpoint), 'push request failed'),
                    (ValueError(endpoint), 'Invalid push data'),
                    (UserError('Invalid push service endpoint.'),
                        'Invalid push service endpoint.'),
                    (WebPushException(endpoint), 'push request failed'),
                    (WebPushException(endpoint, response=SimpleNamespace(
                        status_code=403, text=endpoint)), 'HTTP 403'),
                    (WebPushException(endpoint, response=SimpleNamespace(
                        status_code=503, text=endpoint)), 'HTTP 503'),
                    ]:
                with self.subTest(exception=type(exception), expected=expected):
                    delivery, = Message.publish(app, UserT(user.id),
                        title='Diagnostics', body='Test').deliveries
                    with patch('pywebpush.webpush', side_effect=exception):
                        Delivery.send([delivery])
                    delivery = Delivery(delivery.id)
                    self.assertIn(expected, delivery.error)
                    self.assertIn(type(exception).__name__, delivery.error_traceback)
                    self.assertIn('notification.py', delivery.error_traceback)
                    self.assertNotIn('secret-device-token', delivery.error_traceback)
                    self.assertNotIn(endpoint, delivery.error)
                    self.assertEqual(delivery.attempts, 1)
                    self.assertEqual(delivery.state,
                        'failed' if expected == 'HTTP 403' else 'pending')
                    Delivery.write([delivery], {
                        'state': 'pending',
                        'next_attempt': datetime.now() - timedelta(seconds=1)})
                    with patch('pywebpush.webpush', return_value=SimpleNamespace(
                            status_code=201)):
                        Delivery.send([delivery])
                    delivery = Delivery(delivery.id)
                    self.assertEqual(delivery.state, 'accepted')
                    self.assertFalse(delivery.error)
                    self.assertFalse(delivery.error_traceback)
            delivery, = Message.publish(app, UserT(user.id),
                title='Retry limit', body='Test').deliveries
            Delivery.write([delivery], {'attempts': 4})
            with patch('pywebpush.webpush', side_effect=requests.Timeout(endpoint)):
                Delivery.send([delivery])
            self.assertEqual(delivery.state, 'failed')
            self.assertEqual(delivery.attempts, 5)
