from setuptools import setup

setup(
    name='trytond_notification_web_push', version='7.8.0',
    description='Reusable customer inbox, scheduled messages and Web Push for Tryton',
    packages=['trytond.modules.notification_web_push'],
    package_dir={'trytond.modules.notification_web_push': '.'},
    package_data={'trytond.modules.notification_web_push': [
        'tryton.cfg', '*.xml', 'view/*.xml', 'locale/*.po', 'README.md',
        'requirements.txt']},
    install_requires=['trytond>=7.8,<7.9', 'trytond_company>=7.8,<7.9',
        'trytond_web_user>=7.8,<7.9', 'pywebpush==2.0.3', 'py-vapid==1.9.4',
        'user-agents==2.2.0'],
    entry_points={'trytond.modules': [
        'notification_web_push = trytond.modules.notification_web_push']})
