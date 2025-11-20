import accounts
from django.shortcuts import render, redirect, get_object_or_404
from .forms import RegistrationForm, UserForm, UserProfileForm
from .models import Account, UserProfile
from django.contrib import messages, auth
from django.contrib.auth.decorators import login_required

# Email verification imports
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage
from django.http import HttpResponse

from carts.models import Cart, CartItem
from carts.views import _get_cart_id
from orders.models import Order, OrderItem
import requests


def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            email = form.cleaned_data['email']
            phone_number = form.cleaned_data['phone_number']
            password = form.cleaned_data['password']
            username = email.split('@')[0]

            user = Account.objects.create_user(
                first_name=first_name,
                last_name=last_name,
                username=username,
                email=email,
                password=password
            )
            user.phone_number = phone_number
            user.save()

            current_site = get_current_site(request)
            mail_subject = "Confirm the activation of your account."
            message = render_to_string('accounts/account_verification_email.html', {
                'user': user,
                'domain': current_site,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })
            to_email = email
            send_email = EmailMessage(mail_subject, message, to=[to_email])
            send_email.send()

            return redirect('/accounts/login/?command=verification&email=' + email)
    else:
        form = RegistrationForm()

    return render(request, 'accounts/register.html', {'form': form})


def login(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']

        user = auth.authenticate(username=email, password=password)

        if user is not None:
            try:
                cart = Cart.objects.get(cart_id=_get_cart_id(request))
                cart_item_exists = CartItem.objects.filter(cart=cart).exists()

                if cart_item_exists:
                    cart_item = CartItem.objects.filter(cart=cart)
                    product_variations = []

                    for item in cart_item:
                        variation = list(item.variation.all())
                        product_variations.append(variation)

                    cart_item_user = CartItem.objects.filter(user=user)
                    existing_variations_list = []
                    ids = []

                    for item in cart_item_user:
                        existing_variation = list(item.variation.all())
                        existing_variations_list.append(existing_variation)
                        ids.append(item.id)

                    for product_variation in product_variations:
                        if product_variation in existing_variations_list:
                            index = existing_variations_list.index(product_variation)
                            item_id = ids[index]
                            item = CartItem.objects.get(id=item_id)
                            item.quantity += 1
                            item.user = user
                            item.save()
                        else:
                            cart_item = CartItem.objects.filter(cart=cart)
                            for item in cart_item:
                                item.user = user
                                item.save()

            except:
                pass

            auth.login(request, user)
            messages.success(request, "Logged in Successfully")

            url = request.META.get('HTTP_REFERER')
            try:
                query = requests.utils.urlparse(url).query
                params = dict(x.split('=') for x in query.split('&'))

                if 'next' in params:
                    return redirect(params['next'])

            except:
                return redirect('accounts:dashboard')

        else:
            messages.error(request, "Invalid login Credentials")
            return redirect('accounts:login')

    return render(request, 'accounts/login.html')


@login_required(login_url='accounts:login')
def logout(request):
    auth.logout(request)
    messages.success(request, "Logged out Successfully")
    return redirect('accounts:login')


def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except:
        user = None

    if user and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, "Your account is verified and activated.")
        return redirect('accounts:login')
    else:
        messages.error(request, "Invalid activation link")
        return redirect('accounts:register')


@login_required(login_url='accounts:login')
def dashboard(request):
    orders = Order.objects.filter(user=request.user, is_ordered=True).order_by('-created_at')
    orders_count = orders.count()

    # FIX: UserProfile missing → auto-create
    user_profile, created = UserProfile.objects.get_or_create(user=request.user)

    context = {
        'orders_count': orders_count,
        'user_profile': user_profile,
    }
    return render(request, 'accounts/dashboard.html', context)


def forgot_password(request):
    if request.method == 'POST':
        email = request.POST['email']

        if Account.objects.filter(email=email).exists():
            user = Account.objects.get(email=email)

            current_site = get_current_site(request)
            mail_subject = "Reset Your Password"
            message = render_to_string('accounts/reset_password_email.html', {
                'user': user,
                'domain': current_site,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })

            send_email = EmailMessage(mail_subject, message, to=[email])
            send_email.send()

            messages.success(request, "Reset password email sent!")
            return redirect('accounts:login')

        messages.error(request, "Account not found.")
        return redirect('accounts:forgot_password')

    return render(request, 'accounts/forgot_password.html')


def reset_passwordValidation(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account.objects.get(pk=uid)
    except:
        user = None

    if user and default_token_generator.check_token(user, token):
        request.session['uid'] = uid
        messages.success(request, "Create new password.")
        return redirect('accounts:reset_password')
    else:
        messages.error(request, "Invalid or expired link.")
        return redirect('accounts:forgot_password')


def reset_password(request):
    if request.method == 'POST':
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        if password == confirm_password:
            uid = request.session.get('uid')
            user = Account.objects.get(pk=uid)
            user.set_password(password)
            user.save()

            messages.success(request, "Password reset successful!")
            return redirect('accounts:login')
        else:
            messages.error(request, "Passwords don't match!")
            return redirect('accounts:reset_password')

    return render(request, 'accounts/reset_password.html')


@login_required(login_url='accounts:login')
def my_orders(request):
    orders = Order.objects.filter(user=request.user, is_ordered=True).order_by('-created_at')
    return render(request, 'accounts/my_orders.html', {'orders': orders})


@login_required(login_url='accounts:login')
def edit_profile(request):
    user_profile = get_object_or_404(UserProfile, user=request.user)

    if request.method == 'POST':
        user_form = UserForm(request.POST, instance=request.user)
        profile_form = UserProfileForm(request.POST, request.FILES, instance=user_profile)

        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()

            messages.success(request, "Profile updated!")
            return redirect('accounts:edit_profile')

    else:
        user_form = UserForm(instance=request.user)
        profile_form = UserProfileForm(instance=user_profile)

    return render(request, 'accounts/edit_profile.html', {
        'user_form': user_form,
        'user_profile_form': profile_form,
        'user_profile': user_profile,
    })


@login_required(login_url='accounts:login')
def change_password(request):
    if request.method == 'POST':
        current = request.POST['current_password']
        new = request.POST['new_password']
        confirm = request.POST['confirm_new_password']

        user = Account.objects.get(username=request.user.username)

        if new == confirm:
            if user.check_password(current):
                user.set_password(new)
                user.save()
                messages.success(request, "Password updated!")
                return redirect('accounts:change_password')
            else:
                messages.error(request, "Current password incorrect!")
        else:
            messages.error(request, "Passwords don't match!")

        return redirect('accounts:change_password')

    return render(request, 'accounts/change_password.html')


@login_required(login_url='accounts:login')
def order_detail(request, order_id):
    order_detail = OrderItem.objects.filter(order__order_number=order_id)
    order = Order.objects.get(order_number=order_id)

    subtotal = sum(i.product_price * i.quantity for i in order_detail)

    return render(request, 'accounts/order_detail.html', {
        'order_detail': order_detail,
        'order': order,
        'subtotal': subtotal,
    })
