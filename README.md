# API Сервис заказа товаров для розничных сетей

## Описание

Приложение предназначено для автоматизации закупок в розничной сети через REST API.

### Клиент (покупатель):

- делает ежедневные закупки по каталогу, в котором представлены товары от нескольких поставщиков,
- в одном заказе можно указать товары от разных поставщиков,
- пользователь может авторизироваться, регистрироваться и восстанавливать пароль через API.
### Поставщик:

- через API информирует сервис об обновлении прайса,
- может включать и отключать приём заказов,
- может получать список оформленных заказов (с товарами из его прайса).

## Установка

1. Склонируйте репозиторий с помощью git:

    ```
    git clone https://github.com/kanadass/diplom_dj.git
    ```
   
2. Создайте и заполните .env файл в директории diplom_dj:

    ```
    SECRET_KEY=key
    DEBUG=True
    ALLOWED_HOSTS=localhost
    DB_ENGINE=your_db_engine
    DB_USER=your_db_user
    DB_NAME=your_db_name
    DB_PASSWORD=your_db_password
    DB_HOST=your_db_host
    DB_PORT=5432
    DATABASE=your_database
    EMAIL_HOST_USER=your_email
    EMAIL_HOST_PASSWORD=your_app_password
    EMAIL_PORT=465
    EMAIL_USE_SSL=True
    CELERY_BROKER_URL=redis://:6379/0
    CELERY_RESULT_BACKEND=redis://redis:6379/0
    ```

3. Создайте и заполните .env.db файл в директории diplom_dj:

    ```
    POSTGRES_USER=your_db_user
    POSTGRES_PASSWORD=your_db_password
    POSTGRES_DB=your_db_name
    ```
4. Создайте Docker образы и запустите контейнеры:
    ```
    docker-compose up --build
    ```
5. Создайте суперпользователя:
    ```
    docker-compose exec web python manage.py createsuperuser
    ```

Приложение будет доступно по адресу: [http://127.0.0.1:80/](http://127.0.0.1:80/)

Документация по API: [Swagger](http://127.0.0.1:8000/api/schema/swagger-ui/)