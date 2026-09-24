from trytond.pool import Pool
from . import notification


def register():
    Pool.register(
        notification.Application, notification.Template,
        notification.Preference, notification.Subscription,
        notification.ScheduledMessage, notification.ScheduledMessageUser,
        notification.Message, notification.Delivery, notification.Cron,
        module='notification_web_push', type_='model')
