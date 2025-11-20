from django.shortcuts import render
from store.models import Product
from store.models import ReviewAndRating


def home(request):
    products = Product.objects.all().filter(is_available=True).order_by('-date_created')

    # Get the reviews of products 
    reviews = None 
    for product in products:
        reviews = ReviewAndRating.objects.filter(product_id=product.id, status=True)

    context = {
        'products': products,
        'reviews': reviews,
    }
    return render(request, 'home.html', context)