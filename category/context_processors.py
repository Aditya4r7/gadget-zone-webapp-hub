from .models import Category

def categories_links(request):
    category_links = Category.objects.all()
    return dict(category_links=category_links)