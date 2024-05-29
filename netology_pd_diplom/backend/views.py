from copy import deepcopy
from distutils.util import strtobool

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiParameter, OpenApiExample
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.db import IntegrityError
from django.db.models import Q, Sum, F
from django.http import JsonResponse
from rest_framework.authtoken.models import Token
from rest_framework.generics import ListAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from ujson import loads as load_json
from rest_framework import status


from rest_framework.throttling import UserRateThrottle, AnonRateThrottle

from backend.models import Shop, Category, ProductInfo, Order, OrderItem, \
    Contact, ConfirmEmailToken
from backend.serializers import UserSerializer, CategorySerializer, ShopSerializer, ProductInfoSerializer, \
    OrderItemSerializer, OrderSerializer, ContactSerializer, EmailTokenSerializer, LoginSerializer
from backend.tasks import new_user_registered, new_order, do_import

from backend.permissions import IsOwner


class RegisterAccount(APIView):
    """Для регистрации покупателей """
    throttle_scope = 'register'

    @extend_schema(
        summary="Create a new user account",
        request=UserSerializer,
        responses={
            201: OpenApiResponse(description="User successfully registered."),
            400: OpenApiResponse(description="Missing required fields."),
            403: OpenApiResponse(description="Password validation errors or other errors.")
        }
    )

    def post(self, request, *args, **kwargs):
        """Метод post проверяет наличие обязательных полей,
                и сохраняет пользователя в системе."""

        # проверяем обязательные аргументы
        if {'first_name', 'last_name', 'email', 'password', 'company', 'position'}.issubset(self.request.data):
            errors = {}
            # проверяем пароль на сложность
            try:
                validate_password(request.data['password'])
            except Exception as password_error:
                error_array = []
                # noinspection PyTypeChecker
                for item in password_error:
                    error_array.append(item)
                return Response({'Status': False, 'Errors': {'password': error_array}},
                                status=status.HTTP_403_FORBIDDEN)
            else:
                # проверяем данные для уникальности имени пользователя
                request.POST._mutable = True
                request.data.update({})
                user_serializer = UserSerializer(data=request.data)
                if user_serializer.is_valid():
                    # сохраняем пользователя
                    user = user_serializer.save()
                    user.set_password(request.data['password'])
                    user.save()
                    # new_user_registered.send(sender=self.__class__, user_id=user.id)
                    new_user_registered.delay(user_id=user.id)

                    return Response({'Status': True}, status=status.HTTP_201_CREATED)
                else:
                    return Response({'Status': False, 'Errors': user_serializer.errors},
                                    status=status.HTTP_403_FORBIDDEN)

        return Response({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'},
                        status=status.HTTP_400_BAD_REQUEST)

class ConfirmAccount(APIView):
    """
    Класс для подтверждения почтового адреса
    """

    throttle_classes = (AnonRateThrottle,)


    @extend_schema(
        summary="Confirm user email",
        request=EmailTokenSerializer,
        responses={
            200: OpenApiResponse(description="Email successfully confirmed."),
            400: OpenApiResponse(description="Missing required fields."),
            403: OpenApiResponse(description="Invalid token or email.")
        }
    )

    # Регистрация методом POST
    def post(self, request, *args, **kwargs):
        """
                Подтверждает почтовый адрес пользователя.

                Args:
                - request (Request): The Django request object.

                Returns:
                - JsonResponse: The response indicating the status of the operation and any errors.
                """
        # проверяем обязательные аргументы
        if {'email', 'token'}.issubset(request.data):

            token = ConfirmEmailToken.objects.filter(user__email=request.data['email'],
                                                     key=request.data['token']).first()
            if token:
                token.user.is_active = True
                token.user.save()
                token.delete()
                return JsonResponse({'Status': True})
            else:
                return JsonResponse({'Status': False, 'Errors': 'Неправильно указан токен или email'})

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})


class AccountDetails(APIView):
    """
    A class for managing user account details.

    Methods:
    - get: Retrieve the details of the authenticated user.
    - post: Update the account details of the authenticated user.

    Attributes:
    - None
    """

    permission_classes = [IsAuthenticated, IsOwner]
    throttle_classes = (UserRateThrottle,)

    @extend_schema(
        summary="Retrieve user account details",
        description="Retrieve the details of the authenticated user.",
        responses={
            200: UserSerializer,
            403: OpenApiResponse(description="Log in required.")
        }
    )

    # получить данные
    def get(self, request: Request, *args, **kwargs):
        """
               Retrieve the details of the authenticated user.

               Args:
               - request (Request): The Django request object.

               Returns:
               - Response: The response containing the details of the authenticated user.
        """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        serializer = UserSerializer(request.user)
        return Response(serializer.data)

    @extend_schema(
        summary="Update user account details",
        request=UserSerializer,
        responses={
            200: OpenApiResponse(description="Account details updated successfully."),
            400: OpenApiResponse(description="Validation errors."),
            403: OpenApiResponse(description="Log in required.")
        }
    )

    # Редактирование методом POST
    def post(self, request, *args, **kwargs):
        """
                Update the account details of the authenticated user.

                Args:
                - request (Request): The Django request object.

                Returns:
                - JsonResponse: The response indicating the status of the operation and any errors.
                """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)
        # проверяем обязательные аргументы

        if 'password' in request.data:
            errors = {}
            # проверяем пароль на сложность
            try:
                validate_password(request.data['password'])
            except Exception as password_error:
                error_array = []
                # noinspection PyTypeChecker
                for item in password_error:
                    error_array.append(item)
                return JsonResponse({'Status': False, 'Errors': {'password': error_array}})
            else:
                request.user.set_password(request.data['password'])

        # проверяем остальные данные
        user_serializer = UserSerializer(request.user, data=request.data, partial=True)
        if user_serializer.is_valid():
            user_serializer.save()
            return JsonResponse({'Status': True})
        else:
            return JsonResponse({'Status': False, 'Errors': user_serializer.errors})


class LoginAccount(APIView):
    """
    Класс для авторизации пользователей
    """

    throttle_classes = (AnonRateThrottle,)

    @extend_schema(
        summary="Authenticate user",
        request=LoginSerializer,
        responses={
            200: OpenApiResponse(description="User successfully authenticated."),
            400: OpenApiResponse(description="Missing required fields."),
            403: OpenApiResponse(description="Authentication failed.")
        }
    )

    # Авторизация методом POST
    def post(self, request, *args, **kwargs):
        """
                Authenticate a user.

                Args:
                    request (Request): The Django request object.

                Returns:
                    JsonResponse: The response indicating the status of the operation and any errors.
                """
        if {'email', 'password'}.issubset(request.data):
            user = authenticate(request, username=request.data['email'], password=request.data['password'])

            if user is not None:
                if user.is_active:
                    token, _ = Token.objects.get_or_create(user=user)

                    return JsonResponse({'Status': True, 'Token': token.key})

            return JsonResponse({'Status': False, 'Errors': 'Не удалось авторизовать'})

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})


class CategoryView(ListAPIView):
    """
    Класс для просмотра категорий
    """
    queryset = Category.objects.all()
    serializer_class = CategorySerializer


class ShopView(ListAPIView):
    """
    Класс для просмотра списка магазинов
    """
    queryset = Shop.objects.filter(state=True)
    serializer_class = ShopSerializer


class ProductInfoView(APIView):
    """
        A class for searching products.

        Methods:
        - get: Retrieve the product information based on the specified filters.

        Attributes:
        - None
        """

    throttle_classes = (AnonRateThrottle,)


    @extend_schema(
        summary="Retrieve product information",
        parameters=[
            OpenApiParameter(name='shop_id', description='ID of the shop', required=False, type=int),
            OpenApiParameter(name='category_id', description='ID of the category', required=False, type=int)
        ],
        responses={
            200: ProductInfoSerializer(many=True),
            400: OpenApiResponse(description="Invalid query parameters.")
        }
    )

    def get(self, request: Request, *args, **kwargs):
        """
               Retrieve the product information based on the specified filters.

               Args:
               - request (Request): The Django request object.

               Returns:
               - Response: The response containing the product information.
               """
        query = Q(shop__state=True)
        shop_id = request.query_params.get('shop_id')
        category_id = request.query_params.get('category_id')

        if shop_id:
            query = query & Q(shop_id=shop_id)

        if category_id:
            query = query & Q(product__category_id=category_id)

        # фильтруем и отбрасываем дупликаты
        queryset = ProductInfo.objects.filter(
            query).select_related(
            'shop', 'product__category').prefetch_related(
            'product_parameters__parameter').distinct()

        serializer = ProductInfoSerializer(queryset, many=True)

        return Response(serializer.data)


class BasketView(APIView):
    """
    A class for managing the user's shopping basket.

    Methods:
    - get: Retrieve the items in the user's basket.
    - post: Add an item to the user's basket.
    - put: Update the quantity of an item in the user's basket.
    - delete: Remove an item from the user's basket.

    Attributes:
    - None
    """

    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    @extend_schema(
        summary="Retrieve items in the user's basket",
        responses={
            200: OrderSerializer(many=True),
            403: OpenApiResponse(description="Log in required.")
        }
    )
    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)
        basket = Order.objects.filter(
            user_id=request.user.id, state='basket').prefetch_related(
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter').annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))).distinct()

        serializer = OrderSerializer(basket, many=True)
        return Response(serializer.data)

    @extend_schema(
        summary="Add an item to the user's basket",
        request={
            'application/json': {
                'type': 'object',
                'properties': {
                    'items': {
                        'type': 'array',
                        'items': {
                            'type': 'object',
                            'properties': {
                                'product_info': {'type': 'integer'},
                                'quantity': {'type': 'integer'}
                            }
                        }
                    }
                },
                'example': {
                    'items': [
                        {
                            'product_info': 1,
                            'quantity': 2
                        },
                        {
                            'product_info': 2,
                            'quantity': 1
                        }
                    ]
                }
            }
        },
        responses={
            200: OpenApiResponse(description="Items successfully added to the basket."),
            400: OpenApiResponse(description="Validation errors."),
            403: OpenApiResponse(description="Log in required.")
        }
    )

    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        items_data = request.data.get('items')
        if isinstance(items_data, list):
            basket, _ = Order.objects.get_or_create(user_id=request.user.id, state='basket')
            objects_created = 0
            errors = []

            for order_item in items_data:
                if isinstance(order_item, dict):
                    order_item['order'] = basket.id
                    serializer = OrderItemSerializer(data=order_item)
                    if serializer.is_valid():
                        try:
                            serializer.save()
                            objects_created += 1
                        except IntegrityError as error:
                            errors.append(str(error))
                    else:
                        errors.append(serializer.errors)
                else:
                    errors.append('Order item should be a dictionary')

            if errors:
                return JsonResponse({'Status': False, 'Errors': errors})

            return JsonResponse({'Status': True, 'Создано объектов': objects_created})
        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы или неверный формат данных'})

    @extend_schema(
        summary="Remove an item from the user's basket",
        parameters=[
            OpenApiParameter(
                "items_id",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                description="Comma-separated list of item IDs to be removed from the basket",
                examples =[
                    OpenApiExample(
                        name='Example',
                        value='1,2,3'
                    ),
                ],
            ),
        ],
        responses={
            200: OpenApiResponse(description="Item successfully removed from the basket."),
            403: OpenApiResponse(description="Log in required.")
        }
    )

    # удалить товары из корзины
    def delete(self, request, *args, **kwargs):
        """
                Remove  items from the user's basket.

                Args:
                - request (Request): The Django request object.

                Returns:
                - JsonResponse: The response indicating the status of the operation and any errors.
                """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        items_sting = request.query_params.get('items_id')
        if items_sting:
            items_list = items_sting.split(',')
            basket, _ = Order.objects.get_or_create(user_id=request.user.id, state='basket')
            query = Q()
            objects_deleted = False
            for order_item_id in items_list:
                if order_item_id.isdigit():
                    query = query | Q(order_id=basket.id, id=order_item_id)
                    objects_deleted = True

            if objects_deleted:
                deleted_count = OrderItem.objects.filter(query).delete()[0]
                return JsonResponse({'Status': True, 'Удалено объектов': deleted_count})
        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})

    @extend_schema(
        summary="Update the quantity of an item in the user's basket",
        request={
            'application/json': {
                'type': 'object',
                'properties': {
                    'items': {
                        'type': 'array',
                        'items': {
                            'type': 'object',
                            'properties': {
                                'product_info': {'type': 'integer'},
                                'quantity': {'type': 'integer'}
                            }
                        }
                    }
                },
                'example': {
                    'items': [
                        {
                            'product_info': 1,
                            'quantity': 2
                        },
                        {
                            'product_info': 2,
                            'quantity': 1
                        }
                    ]
                }
            }
        },
        responses={
            200: OpenApiResponse(description="Items successfully updated in the basket."),
            400: OpenApiResponse(description="Validation errors."),
            403: OpenApiResponse(description="Log in required.")
        }
    )

    # добавить позиции в корзину
    def put(self, request, *args, **kwargs):
        """
        Update the items in the user's basket.

        Args:
        - request (Request): The Django request object.

        Returns:
        - JsonResponse: The response indicating the status of the operation and any errors.
        """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        items_list = request.data.get('items')
        if items_list:
            try:
                # Проверка типа данных items_list
                if not isinstance(items_list, list):
                    raise ValueError
            except ValueError:
                return JsonResponse({'Status': False, 'Errors': 'Неверный формат запроса'})
            else:
                basket, _ = Order.objects.get_or_create(user_id=request.user.id, state='basket')
                objects_updated = 0
                for order_item in items_list:
                    if isinstance(order_item['product_info'], int) and isinstance(order_item['quantity'], int):
                        objects_updated += OrderItem.objects.filter(order_id=basket.id,
                                                                    product_info_id=order_item['product_info']).update(
                            quantity=order_item['quantity'])

                return JsonResponse({'Status': True, 'Обновлено объектов': objects_updated})
        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})


class PartnerUpdate(APIView):
    """
    Класс для обновления прайса от поставщика
    """
    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    @extend_schema(
        summary="Update price from supplier",
        request={
            'application/json': {
                'type': 'object',
                'properties': {
                    'url': {
                        'type': 'string',
                        'format': 'uri',
                        'description': 'URL to the price list file'
                    }
                },
                'example': {
                    'url': 'https://raw.githubusercontent.com/netology-code/pd-diplom/master/data/shop1.yaml'
                }
            }
        },
        responses={
            200: OpenApiResponse(description="Price list update initiated successfully."),
            400: OpenApiResponse(description="All necessary arguments are not specified."),
            403: OpenApiResponse(description="Log in required or user is not a shop.")
        }
    )

    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'},
                                status=status.HTTP_403_FORBIDDEN)

        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Error': 'For shops only'},
                                status=status.HTTP_403_FORBIDDEN)

        url = request.data.get('url')
        if url:
            try:
                do_import.delay(url, request.user.id)
            except IntegrityError as e:
                return JsonResponse({'Status': False,
                                     'Errors': f'Integrity Error: {e}'})

            return JsonResponse({'Status': True}, status=status.HTTP_200_OK)

        return JsonResponse({'Status': False, 'Errors': 'All necessary arguments are not specified'},
                            status=status.HTTP_400_BAD_REQUEST)


class PartnerState(APIView):
    """
       A class for managing partner state.

       Methods:
       - get: Retrieve the state of the partner.

       Attributes:
       - None
       """

    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    @extend_schema(
        summary="Retrieve the state of the partner",
        responses={
            200: ShopSerializer,
            403: OpenApiResponse(description="Log in required or only for shops."),
            404: OpenApiResponse(description="Shop not found for the user."),
        },
    )

    # получить текущий статус
    def get(self, request, *args, **kwargs):
        """
               Retrieve the state of the partner.

               Args:
               - request (Request): The Django request object.

               Returns:
               - Response: The response containing the state of the partner.
               """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Error': 'Только для магазинов'}, status=403)

        shop = request.user.shop
        serializer = ShopSerializer(shop)
        return Response(serializer.data)

    @extend_schema(
        summary="Update the state of the partner",
        parameters=[
            OpenApiParameter(
                name="state",
                type={'type': 'boolean'},
                location=OpenApiParameter.QUERY,
                description="The new state of the shop. True for active, False for inactive.",
            )
        ],
        responses={
            200: OpenApiResponse(description="State updated successfully."),
            400: OpenApiResponse(description="Invalid arguments or ValueError."),
            403: OpenApiResponse(description="Log in required or only for shops.")
        }
    )

    # изменить текущий статус
    def post(self, request, *args, **kwargs):
        """
        Update the state of a partner.

        Args:
        - request (Request): The Django request object.

        Returns:
        - JsonResponse: The response indicating the status of the operation and any errors.
        """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Error': 'Только для магазинов'}, status=403)

        state = request.query_params.get('state')
        if state is not None:
            try:
                Shop.objects.filter(user_id=request.user.id).update(state=bool(strtobool(state)))
                return JsonResponse({'Status': True})
            except ValueError as error:
                return JsonResponse({'Status': False, 'Errors': str(error)}, status=400)

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'}, status=400)


class PartnerOrders(APIView):
    """
    Класс для получения заказов поставщиками
     Methods:
    - get: Retrieve the orders associated with the authenticated partner.

    Attributes:
    - None
    """

    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    @extend_schema(
        summary="Retrieve orders associated with the authenticated partner.",
        responses={
            200: OrderSerializer(many=True),
            403: OpenApiResponse(description="Log in required.")
        }
    )

    def get(self, request, *args, **kwargs):
        """
               Retrieve the orders associated with the authenticated partner.

               Args:
               - request (Request): The Django request object.

               Returns:
               - Response: The response containing the orders associated with the partner.
               """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        if request.user.type != 'shop':
            return JsonResponse({'Status': False, 'Error': 'Только для магазинов'}, status=403)

        order = Order.objects.filter(
            ordered_items__product_info__shop__user_id=request.user.id).exclude(state='basket').prefetch_related(
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter').select_related('contact').annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))).distinct()

        if not order.exists():
            print("No orders found for this partner.")

        serializer = OrderSerializer(order, many=True)
        return Response(serializer.data)


class ContactView(APIView):
    """
       A class for managing contact information.

       Methods:
       - get: Retrieve the contact information of the authenticated user.
       - post: Create a new contact for the authenticated user.
       - put: Update the contact information of the authenticated user.
       - delete: Delete the contact of the authenticated user.

       Attributes:
       - None
       """

    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    @extend_schema(
        summary="Retrieve contact information of the authenticated user.",
        responses={
            200: ContactSerializer(many=True),
            403: OpenApiResponse(description="Log in required.")
        }
    )

    # получить мои контакты
    def get(self, request, *args, **kwargs):
        """
       Retrieve the contact information of the authenticated user.

       Args:
       - request (Request): The Django request object.

       Returns:
       - Response: The response containing the contact information.
        """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)
        contact = Contact.objects.filter(
            user_id=request.user.id)
        serializer = ContactSerializer(contact, many=True)
        return Response(serializer.data)

    @extend_schema(
        summary='Create a new contact for the authenticated user',
        request=ContactSerializer,
        responses={
            200: ContactSerializer(many=True),
            400: OpenApiResponse(description="Validation errors."),
            403: OpenApiResponse(description="Log in required.")
        },
    )

    # добавить новый контакт
    def post(self, request, *args, **kwargs):
        """
        Create a new contact for the authenticated user.
        """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        required_fields = {'city', 'street', 'phone'}
        if required_fields.issubset(request.data):
            mutable_data = deepcopy(request.data)  # Create a mutable copy
            mutable_data.update({'user': request.user.id})
            serializer = ContactSerializer(data=mutable_data)

            if serializer.is_valid():
                serializer.save()
                return JsonResponse({'Status': True})
            else:
                return JsonResponse({'Status': False, 'Errors': serializer.errors})

        return JsonResponse({'Status': False, 'Errors': 'Not all required arguments are specified'})

    @extend_schema(
        parameters=[
            OpenApiParameter(
                "items",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                description="Comma-separated list of contact IDs to delete.",
                examples=[
                    OpenApiExample(
                        name='Example',
                        value='1,2,3'
                    ),
                ],
            ),
        ],
        responses={
            200: OpenApiResponse(description="Contacts successfully deleted."),
            400: OpenApiResponse(description="All necessary arguments are not specified."),
            403: OpenApiResponse(description="Log in required.")
        }
    )

    def delete(self, request, *args, **kwargs):
        """
        Delete the contact of the authenticated user.

        Args:
        - request (Request): The Django request object.

        Returns:
        - JsonResponse: The response indicating the status of the operation and any errors.
        """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        items_string = request.query_params.get('items')
        if items_string:
            items_list = items_string.split(',')
            query = Q()
            objects_deleted = False
            for contact_id in items_list:
                if contact_id.isdigit():
                    query = query | Q(user_id=request.user.id, id=contact_id)
                    objects_deleted = True

            if objects_deleted:
                deleted_count = Contact.objects.filter(query).delete()[0]
                return JsonResponse({'Status': True, 'Удалено объектов': deleted_count})
        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'}, status=400)

    @extend_schema(
        summary="Update the contact information of the authenticated user",
        request={
            'application/json': {
                'type': 'object',
                'properties': {
                    'id': {'type': 'string'},
                    'city': {'type': 'string'},
                    'street': {'type': 'string'},
                    'house': {'type': 'string'},
                    'structure': {'type': 'string'},
                    'building': {'type': 'string'},
                    'apartment': {'type': 'string'},
                    'phone': {'type': 'string'},
                },
                'example': {
                    'id': '1',
                    'city': 'string',
                    'street': 'string',
                    'house': 'string',
                    'structure': 'string',
                    'building': 'string',
                    'apartment': 'string',
                    'phone': 'string',
                }
            }
        },
        responses={
            200: OpenApiResponse(description="Contact successfully updated."),
            400: OpenApiResponse(description="Validation errors."),
            403: OpenApiResponse(description="Log in required.")
        }
    )

    # редактировать контакт
    def put(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            """
                   Update the contact information of the authenticated user.

                   Args:
                   - request (Request): The Django request object.

                   Returns:
                   - JsonResponse: The response indicating the status of the operation and any errors.
                   """
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        if 'id' in request.data:
            if request.data['id'].isdigit():
                contact = Contact.objects.filter(id=request.data['id'], user_id=request.user.id).first()
                print(contact)
                if contact:
                    serializer = ContactSerializer(contact, data=request.data, partial=True)
                    if serializer.is_valid():
                        serializer.save()
                        return JsonResponse({'Status': True})
                    else:
                        return JsonResponse({'Status': False, 'Errors': serializer.errors})

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})


class OrderView(APIView):
    """
    Класс для получения и размешения заказов пользователями
    Methods:
    - get: Retrieve the details of a specific order.
    - post: Create a new order.
    - put: Update the details of a specific order.
    - delete: Delete a specific order.

    Attributes:
    - None
    """

    permission_classes = (IsAuthenticated,)
    throttle_classes = (UserRateThrottle,)

    @extend_schema(
        summary="Retrieve user orders",
        responses={
            200: OrderSerializer(many=True),
            403: OpenApiResponse(description="Log in required.")
        }
    )

    # получить мои заказы
    def get(self, request, *args, **kwargs):
        """
               Retrieve the details of user orders.

               Args:
               - request (Request): The Django request object.

               Returns:
               - Response: The response containing the details of the order.
               """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)
        order = Order.objects.filter(
            user_id=request.user.id).exclude(state='basket').prefetch_related(
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter').select_related('contact').annotate(
            total_sum=Sum(F('ordered_items__quantity') * F('ordered_items__product_info__price'))).distinct()

        serializer = OrderSerializer(order, many=True)
        return Response(serializer.data)

    @extend_schema(
        summary="Place an order and send a notification",
        request={
            'application/json': {
                'type': 'object',
                'properties': {
                    'id': {'type': 'string', 'description': 'Order ID'},
                    'contact': {'type': 'string', 'description': 'Contact ID'}
                },
                'example': {
                    'id': '1',
                    'contact': '1'
                }
            }
        },
        responses={
            200: OpenApiResponse(description="Order placed successfully."),
            400: OpenApiResponse(description="Invalid arguments or IntegrityError."),
            403: OpenApiResponse(description="Log in required.")
        }
    )

    # разместить заказ из корзины
    def post(self, request, *args, **kwargs):
        """
               Put an order and send a notification.

               Args:
               - request (Request): The Django request object.

               Returns:
               - JsonResponse: The response indicating the status of the operation and any errors.
               """
        if not request.user.is_authenticated:
            return JsonResponse({'Status': False, 'Error': 'Log in required'}, status=403)

        if {'id', 'contact'}.issubset(request.data):
            if request.data['id'].isdigit():
                try:
                    is_updated = Order.objects.filter(
                        user_id=request.user.id, id=request.data['id']).update(
                        contact_id=request.data['contact'],
                        state='new')
                except IntegrityError as error:
                    print(error)
                    return JsonResponse({'Status': False, 'Errors': 'Неправильно указаны аргументы'})
                else:
                    if is_updated:
                        # new_order.send(sender=self.__class__, user_id=request.user.id)
                        new_order.delay(user_id=request.user.id)
                        return JsonResponse({'Status': True})

        return JsonResponse({'Status': False, 'Errors': 'Не указаны все необходимые аргументы'})




