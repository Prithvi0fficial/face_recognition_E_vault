from django.shortcuts import render

# Create your views here.
# views.py
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from .forms import RegistrationForm
import os
import hashlib

def initial_register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            pin = form.cleaned_data['pin']

            # Create the Django user without password for now
            user = User.objects.create_user(username=username)
            user.save()

            # Save PIN hash in user's data folder
            user_folder = os.path.join('data', username)
            os.makedirs(user_folder, exist_ok=True)

            pin_hash = hashlib.sha256(pin.encode()).hexdigest()
            with open(os.path.join(user_folder, 'pin_hash.txt'), 'w') as f:
                f.write(pin_hash)

            messages.success(request, 'User registered successfully! Please login.')
            return redirect('user_pin_login')  # your login url name

    else:
        form = RegistrationForm()

    return render(request, 'users/initial_register.html', {'form': form})



# login 
# users/views.py
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import get_user_model, login
from .forms import PINLoginForm
import os
import hashlib

User = get_user_model()

def check_user_pin(user, raw_pin):
    pin_file = os.path.join('data', user.username, 'pin_hash.txt')
    if not os.path.exists(pin_file):
        return False
    with open(pin_file, 'r') as f:
        stored_hash = f.read().strip()
    return stored_hash == hashlib.sha256(raw_pin.encode()).hexdigest()

def pin_login_view(request):
    if request.method == 'POST':
        form = PINLoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            pin = form.cleaned_data['pin']
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                messages.error(request, 'User does not exist.')
                return redirect('pin_login')

            if check_user_pin(user, pin):
                login(request, user)  # sets the session
                messages.success(request, 'Logged in successfully!')
                return redirect('home')  # or vault or dashboard
            else:
                messages.error(request, 'Invalid PIN.')
    else:
        form = PINLoginForm()

    return render(request, 'users/pin_login.html', {'form': form})


from django.contrib.auth import logout
from django.shortcuts import redirect

def logout_view(request):
    logout(request)
    return redirect('user_pin_login')  # Redirect to your login page (adjust the name if needed)
