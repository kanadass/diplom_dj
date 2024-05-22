import pytest
from django.urls import reverse
from rest_framework import status

from backend.models import User


@pytest.mark.django_db
def test_user_create(api_client):
    some_user = {
        "first_name": "name",
        "last_name": "last_name",
        "email": "test@gmail.com",
        "password": "Password123?",
        "company": "Company",
        "position": "Position"
    }

    url = reverse("backend:user-register")
    response = api_client.post(url, data=some_user)

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json().get('Status') is True


@pytest.mark.django_db
def test_user_confirm(api_client, user_factory, confirm_email_token_factory):
    user = user_factory()
    token = confirm_email_token_factory()
    user.confirm_email_tokens.add(token)
    url = reverse("backend:user-register-confirm")
    response = api_client.post(url, data={"email": user.email, "token": "wrong_key"})
    assert response.status_code == status.HTTP_200_OK
    assert response.json().get('Status') is False
    response = api_client.post(url, data={"email": user.email, "token": token.key})
    assert response.status_code == status.HTTP_200_OK
    assert response.json().get('Status') is True


@pytest.mark.django_db
def test_user_login(api_client, user_factory):
    mail = "test@gmail.com"
    passw = "Password123?"

    some_user = {
        "first_name": "first_name",
        "last_name": "last_name",
        "email": mail,
        "password": passw,
        "company": "Company",
        "position": "Position"
    }

    url = reverse("backend:user-register")
    response = api_client.post(url, data=some_user)
    assert response.json().get('Status') is True

    user = User.objects.get(email=mail)
    user.is_active = True
    user.save()

    url = reverse("backend:user-login")
    response = api_client.post(url, data={"email": mail, "password": passw})
    assert response.status_code == status.HTTP_200_OK
    assert response.json().get('Status') is True


@pytest.mark.django_db
def test_user_details(api_client, user_factory):
    url = reverse("backend:user-details")
    user = user_factory()

    response = api_client.get(url)
    assert response.status_code == status.HTTP_403_FORBIDDEN

    api_client.force_authenticate(user=user)

    response = api_client.get(url)
    assert response.status_code == status.HTTP_200_OK
    assert response.json().get('email') == user.email

    updated_data = {
        "first_name": "Test",
        "last_name": "Test",
        "email": "test@mail.com",
        "password": "Password123?",
        "company": "Company122",
        "position": "Position123"
    }
    response = api_client.post(url, data=updated_data)
    assert response.status_code == status.HTTP_200_OK  # Assuming this is the expected status code

    response = api_client.get(url)
    assert response.json().get('company') == "Company122"

    response = api_client.post(url, data={"type": "shop"})
    assert response.status_code == status.HTTP_200_OK  # Assuming this is the expected status code

    response = api_client.get(url)
    assert response.json().get('type') == "shop"


@pytest.mark.django_db
def test_products(api_client, user_factory, shop_factory, order_factory,
                  product_info_factory, product_factory, category_factory):

    url = reverse("backend:shops")
    shop = shop_factory()
    customer = user_factory()
    category = category_factory()
    prod = product_factory(category=category)
    prod_info = product_info_factory(product=prod, shop=shop)
    api_client.force_authenticate(user=customer)
    shop_id = shop.id
    category_id = category.id
    response = api_client.get(url, shop_id=shop.id, category_id=category.id)
    assert response.status_code == status.HTTP_200_OK
    assert response.json()[0].get('id', False)


@pytest.mark.django_db
def test_partner_upload(api_client, user_factory):
    price = 'https://raw.githubusercontent.com/mexalon/finproj/master/mymazon/data_for_ulpoad/shop1.yml'
    url = reverse("backend:partner-update")
    user = user_factory()
    api_client.force_authenticate(user=user)

    response = api_client.post(url, data={"url": price})
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json().get('Status') is False

    response = api_client.post(reverse("backend:user-details"), data={"type": "shop"})
    response = api_client.get(reverse("backend:user-details"))
    assert response.json().get('type') == "shop"

    response = api_client.post(url, data={"url": price})
    assert response.status_code == status.HTTP_200_OK
    assert response.json().get('Status') is True


@pytest.mark.django_db
def test_category_get(api_client, category_factory):
    url = reverse('backend:categories')
    category_factory(_quantity=4)
    response = api_client.get(url)
    assert response.status_code == 200
    assert len(response.data) == 4



@pytest.mark.django_db
def test_basket_post_by_anonymous_user(api_client):
    payload = {"items": [{"product_info": 1, "quantity": 2}]}
    url = reverse('backend:basket')
    response = api_client.post(url, data=payload)
    assert response.status_code == status.HTTP_403_FORBIDDEN