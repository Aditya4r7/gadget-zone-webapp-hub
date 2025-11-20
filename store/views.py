from django.shortcuts import render, get_object_or_404, redirect
from category.models import Category
from .models import Product, ProductGallery, ReviewAndRating
from carts.models import CartItem
from carts.views import _get_cart_id
from django.core.paginator import EmptyPage, PageNotAnInteger, Paginator
from django.db.models import Q
from .forms import ReviewAndRatingForm
from django.contrib import messages
from orders.models import OrderItem

# Create your views here.
def store(request, category_slug=None):
    categories = None
    products = None
    # categories = Category.objects.all()
    # products = Product.objects.all().filter(is_available=True)

    if category_slug is not None:
        categories = get_object_or_404(Category, slug=category_slug)
        products = Product.objects.all().filter(category=categories, is_available=True)
        paginator = Paginator(products, 1)
        page = request.GET.get('page')
        paged_products = paginator.get_page(page)
        product_count = products.count()
    else:
        products = Product.objects.all().filter(is_available=True).order_by('id')
        paginator = Paginator(products, 3)
        page_number = request.GET.get('page')
        paged_products = paginator.get_page(page_number)
        product_count = products.count()

        
    context = {
        'categories': categories,
         'products': paged_products,
         'product_count': product_count,
         }
    return render(request, 'store/store.html', context)


def product_details(request, category_slug, product_slug):
    try:
        single_product = Product.objects.get(category__slug=category_slug, slug=product_slug)
        in_cart = CartItem.objects.filter(cart__cart_id=_get_cart_id(request), product=single_product).exists()
    except Exception as e:
        raise e

    # checking if user has purchsed a certain product
    if request.user.is_authenticated:
        try:
            order_item = OrderItem.objects.filter(user=request.user, item_id=single_product.id).exists()
        except OrderItem.DoesNotExist:
            order_item = None
    else:
        order_item = None

    # Get the reviews of products
    reviews = ReviewAndRating.objects.filter(product_id=single_product.id, status=True)

    # get the product gallery  
    product_gallery = ProductGallery.objects.filter(product_id=single_product.id)

    context = {
        'single_product': single_product,
        'in_cart': in_cart,
        'product_gallery': product_gallery,
        'order_item': order_item,
        'reviews': reviews,
    }
    return render(request, 'store/product_details.html', context)


def search(request):
    if 'keyword' in request.GET:
        keyword = request.GET['keyword']
        if keyword:
            products = Product.objects.order_by('-date_created').filter(Q(description__icontains=keyword) | Q(product_name__icontains=keyword))
            product_count = products.count()
        else:
            products = None
            product_count = 0
    context = {
        'products': products,
        'product_count': product_count,
    }
    return render(request, 'store/store.html', context)



def submit_review(request, product_id):
    current_url = request.META.get('HTTP_REFERER')
    if request.method == 'POST':
        try:
            reviews = ReviewAndRating.objects.get(user__id=request.user.id, product__id=product_id)
            form = ReviewAndRatingForm(request.POST, instance=reviews)
            form.save()
            messages.success(request, "Thank you! Your Review has been updated.")
            return redirect(current_url)


        except ReviewAndRating.DoesNotExist:
            form = ReviewAndRatingForm(request.POST)
            if form.is_valid():
                data = ReviewAndRating()
                data.subject = form.cleaned_data['subject']
                data.rating = form.cleaned_data['rating']
                data.review = form.cleaned_data['review']
                data.ip = request.META.get('REMOTE_ADDR')
                data.product_id = product_id
                data.user_id = request.user.id
                data.save()
                messages.success(request, "Thank you! Your Review has been submitted successfully.")
                return redirect(current_url)


