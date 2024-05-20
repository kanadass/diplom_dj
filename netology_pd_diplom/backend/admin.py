from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from backend.models import User, Shop, Category, Product, ProductInfo, Parameter, ProductParameter, Order, OrderItem, \
    Contact, ConfirmEmailToken


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    """
    Панель управления пользователями
    """
    model = User

    fieldsets = (
        (None, {'fields': ('email', 'password', 'type')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'company', 'position')}),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),)
    list_display = ('email', 'first_name', 'last_name', 'is_staff')
    ordering = ('email', 'first_name', 'last_name', 'is_staff')
    list_editable = ('is_staff',)
    list_per_page = 10

@admin.register(Shop)
class ShopAdmin(admin.ModelAdmin):
    """
    Панель управления магазинами
    """
    list_display = ('name', 'url', 'user', 'state')
    list_filter = ('name', 'state')


class ProductInline(admin.TabularInline):
    model = Product
    extra = 1


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    """
    Панель управления категориями
    """
    inlines = [ProductInline]


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    """
    Панель управления продуктами
    """
    list_display = ('id', 'name', 'category')
    list_display_links = ('id', 'name')
    ordering = ('name',)
    list_editable = ('category',)
    list_filter = ('id', 'name', 'category')
    search_fields = ('id', 'name', 'category')


class ProductParameterInline(admin.TabularInline):
    model = ProductParameter
    extra = 1


@admin.register(ProductInfo)
class ProductInfoAdmin(admin.ModelAdmin):
    """
    Панель управления информацией о продукте
    """
    list_display = ('product', 'external_id', 'shop', 'price', 'price_rrc', 'quantity')
    inlines = [ProductParameterInline]


@admin.register(Parameter)
class ParameterAdmin(admin.ModelAdmin):
    """
    Панель управления параметрами
    """
    list_display = ('name',)
    search_fields = ('name',)


@admin.register(ProductParameter)
class ProductParameterAdmin(admin.ModelAdmin):
    """
    Панель управления параметрами продукта
    """
    list_display = ('product_info', 'parameter', 'value')
    list_filter = ('parameter', 'value')
    search_fields = ('product_info__product__name', 'parameter__name',)


class OrderItemInline(admin.TabularInline):
    model = OrderItem
    extra = 1


@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    """
    Панель управления заказами
    """
    list_display = ('id', 'user', 'dt', 'state', 'contact')
    list_filter = ('dt', 'state')
    inlines = [OrderItemInline]


@admin.register(OrderItem)
class OrderItemAdmin(admin.ModelAdmin):
    """
    Панель управления заказанными позициями
    """
    list_display = ('id', 'order', 'product_info', 'quantity')


@admin.register(Contact)
class ContactAdmin(admin.ModelAdmin):
    """
    Панель управления контактами
    """
    list_display = ('user', 'city', 'street', 'phone')
    list_filter = ('city', 'street')
    search_fields = ('user__email', 'city', 'street', 'phone')


@admin.register(ConfirmEmailToken)
class ConfirmEmailTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'key', 'created_at',)
