# Generated by Django 5.0.6 on 2024-06-02 11:54

import easy_thumbnails.fields
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('backend', '0002_product_image'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='avatar',
            field=easy_thumbnails.fields.ThumbnailerImageField(blank=True, null=True, upload_to='avatars', verbose_name='Аватар'),
        ),
    ]
