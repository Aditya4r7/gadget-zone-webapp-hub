from django import forms
from .models import ReviewAndRating


class ReviewAndRatingForm(forms.ModelForm):
    class Meta:
        model = ReviewAndRating
        fields = ['subject', 'review', 'rating']