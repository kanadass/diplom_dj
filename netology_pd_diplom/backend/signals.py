from typing import Type

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.db.models.signals import post_save
from django.dispatch import receiver, Signal
from django_rest_passwordreset.signals import reset_password_token_created

from .models import ConfirmEmailToken, User, Product
from .tasks import send_password_reset_email, generate_thumbnails

new_user_registered = Signal()

new_order = Signal()


@receiver(reset_password_token_created)
def password_reset_token_created(sender, instance, reset_password_token, **kwargs):
    # send an e-mail to the user
    send_password_reset_email.delay(reset_password_token.user.email, reset_password_token.key)


@receiver(post_save, sender=User)
def new_user_registered_signal(sender: Type[User], instance: User, created: bool, **kwargs):
    """
     отправляем письмо с подтрердждением почты
    """
    if created and not instance.is_active:
        # send an e-mail to the user
        token, _ = ConfirmEmailToken.objects.get_or_create(user_id=instance.pk)

        msg = EmailMultiAlternatives(
            # title:
            f"Password Reset Token for {instance.email}",
            # message:
            token.key,
            # from:
            settings.EMAIL_HOST_USER,
            # to:
            [instance.email]
        )
        msg.send()


@receiver(new_order)
def new_order_signal(user_id, **kwargs):
    """
    отправяем письмо при изменении статуса заказа
    """
    # send an e-mail to the user
    user = User.objects.get(id=user_id)

    msg = EmailMultiAlternatives(
        # title:
        f"Обновление статуса заказа",
        # message:
        'Заказ сформирован',
        # from:
        settings.EMAIL_HOST_USER,
        # to:
        [user.email]
    )
    msg.send()


@receiver(post_save, sender=Product)
@receiver(post_save, sender=User)
def handle_image_save(sender, instance, **kwargs):
    """
    Обработчик сигнала для создания миниатюр после сохранения объектов Product и User.
    """
    if isinstance(instance, Product) and instance.image:
        generate_thumbnails.delay('Product', instance.id, 'image')
    elif isinstance(instance, User) and instance.avatar:
        generate_thumbnails.delay('User', instance.id, 'avatar')