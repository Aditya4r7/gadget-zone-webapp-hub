from django.shortcuts import render, redirect
from django.http import JsonResponse
from .models import Order, Payment, OrderItem
from carts.models import CartItem
from .forms import OrderForm
from store.models import Product

import datetime
import json

from django.template.loader import render_to_string
from django.core.mail import EmailMessage


def payments(request):
    body = json.loads(request.body)
    order = Order.objects.get(user=request.user, is_ordered=False, order_number=body['order_id'])
    
    # store transaction details into payment model
    payment = Payment(
        user=request.user, 
        payment_id=body['transaction_id'], 
        payment_method=body['payment_method'],
        amount_paid = order.order_total,
        status = body['status'],
    )

    payment.save()
    order.payment = payment
    order.is_ordered = True
    order.save()

    # Move the cart items to order item table after the order
    cart_items = CartItem.objects.filter(user=request.user)

    for item in cart_items:
        order_item = OrderItem()
        order_item.order_id = order.id
        order_item.payment = payment
        order_item.user_id = request.user.id
        order_item.item_id = item.product_id
        order_item.quantity = item.quantity
        order_item.product_price = item.product.price
        order_item.ordered = True
        order_item.save()

        # saving the variation of order item
        cart_item = CartItem.objects.get(id=item.id)
        product_variation = cart_item.variation.all()
        order_item = OrderItem.objects.get(id=order_item.id)
        order_item.variation.set(product_variation)
        order.save()

        # Reduce the quantity of sold products
        product = Product.objects.get(id=item.product_id)
        product.stock -= item.quantity
        product.save()

    # Clear the cart items
    CartItem.objects.filter(user=request.user).delete()

    # Send order confirmed email to customer
    mail_subject = "Your order has been received. Thanks for the purchase!"
    message = render_to_string('orders/order_received_email.html', {
        'user': request.user, 
        'order': order,
    })
    to_email = request.user
    send_email = EmailMessage(mail_subject, message, to=[to_email])
    send_email.send()

    # Send order number and transaction id back to sendPaymentData method via JsonResponse
    paymentData = {
        'order_number': order.order_number,
        'transaction_id': payment.payment_id,
    }
    return JsonResponse(paymentData)


# Create your views here.
def place_order(request, total=0, quantity=0):
    current_user = request.user

    # if there is no item in the cart then send the user back to the store page
    cart_items = CartItem.objects.filter(user=current_user)
    cart_count = cart_items.count()
    if cart_count <= 0:
        return redirect('store:store')

    tax = 0
    grand_total = 0
    for cart_item in cart_items:
        total += (cart_item.product.price * cart_item.quantity)
        quantity += cart_item.quantity
    tax = (5 * total)/100
    grand_total = total + tax

    if request.method == 'POST':
        form = OrderForm(request.POST)
        if form.is_valid():
            # store the billing information inside order table
            data = Order()
            data.user = current_user
            data.first_name = form.cleaned_data['first_name']
            data.last_name = form.cleaned_data['last_name']
            data.phone_number = form.cleaned_data['phone_number']
            data.email = form.cleaned_data['email']
            data.address_line_1 = form.cleaned_data['address_line_1']
            data.address_line_2 = form.cleaned_data['address_line_2']
            data.city = form.cleaned_data['city']
            data.state = form.cleaned_data['state']
            data.country = form.cleaned_data['country']
            data.order_note = form.cleaned_data['order_note']

            data.order_total = grand_total
            data.tax = tax
            data.ip = request.META.get('REMOTE_ADDR')
            data.save()

            # generating order number
            year = int(datetime.date.today().strftime('%Y'))
            month = int(datetime.date.today().strftime('%m'))
            date = int(datetime.date.today().strftime('%d'))

            date_format = datetime.date(year, month, date)
            current_date = date_format.strftime('%Y%m%d')

            order_number = current_date + str(data.id)
            data.order_number = order_number
            data.save()

            order = Order.objects.get(user=current_user, is_ordered=False, order_number=order_number)
            context = {
                'order': order,
                'cart_items':cart_items,
                'total':total,
                'tax':tax,
                'grand_total':grand_total,
            }

            return render(request, 'orders/payments.html', context)
        else:
            return redirect('store:store')

    else:
        return redirect('carts:cart')


def order_complete(request):
    order_number = request.GET.get('order_number')
    transaction_id = request.GET.get('payment_id')

    try:
        order = Order.objects.get(order_number=order_number, is_ordered=True)
        order_items = OrderItem.objects.filter(order_id=order.id)

        subtotal = 0
        for i in order_items:
            subtotal += i.product_price * i.quantity

        payment = Payment.objects.get(payment_id=transaction_id)

        context = {
            'order': order,
            'order_items': order_items,
            'order_number': order.order_number,
            'transaction_id': payment.payment_id,
            'payment': payment,
            'subtotal': subtotal,
        }
        return render(request, 'orders/order_complete.html', context)

    except (Payment.DoesNotExist, Order.DoesNotExist):
        return redirect('home')

    
