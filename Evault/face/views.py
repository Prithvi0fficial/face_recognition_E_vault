from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login
from django.contrib.auth import get_user_model
from django.views.decorators.csrf import csrf_exempt

# Create your views here.

def home(request):
        return render(request,'face/home.html')

User = get_user_model()
def check_user_pin(user, raw_pin):
    pin_file = os.path.join('data', user.username, 'pin_hash.txt')
    if not os.path.exists(pin_file):
        return False
    with open(pin_file, 'r') as f:
        stored_hash = f.read().strip()
    return stored_hash == hashlib.sha256(raw_pin.encode()).hexdigest()



def pin_login(request):
    return render(request, 'pin_login.html')  # Create this HTML template


import os
import base64
import pickle
import hashlib
import numpy as np
from PIL import Image
import face_recognition
from io import BytesIO

# evault/views.py
@login_required
def register_face_page(request):
    return render(request, 'face/face_reg.html')

@csrf_exempt
@login_required
def register_face_api(request):
    if request.method != 'POST':
        return HttpResponseBadRequest('Only POST allowed')

    import json
    try:
        data = json.loads(request.body)
        image_data_url = data.get('image')
        raw_pin = data.get('pin')

        if not image_data_url or not raw_pin:
            return JsonResponse({'status': 'error', 'message': 'Image or PIN missing'}, status=400)

        # Create per-user data folder
        user_folder = os.path.join('data', request.user.username)
        os.makedirs(user_folder, exist_ok=True)

        # Save hashed PIN in user's own file
        hashed_pin = hashlib.sha256(raw_pin.encode()).hexdigest()
        pin_file = os.path.join(user_folder, 'pin_hash.txt')
        with open(pin_file, "w") as f:
            f.write(hashed_pin)

        # Decode and save face encoding
        header, base64_data = image_data_url.split(",", 1)
        image_data = base64.b64decode(base64_data)
        image = Image.open(BytesIO(image_data)).convert('RGB')
        image_np = np.array(image)

        encodings = face_recognition.face_encodings(image_np)
        if not encodings:
            return JsonResponse({'status': 'error', 'message': '❌ No face detected. Try again.'})

        face_file = os.path.join(user_folder, 'face_encoding.pkl')
        with open(face_file, "wb") as f:
            pickle.dump(encodings[0], f)

        return JsonResponse({'status': 'success', 'message': '✅ Face and PIN registered successfully'})

    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)



# face login

# evault/views.py
import json
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from .face_utils import match_face, check_pin

@login_required
def login_page(request):
    return render(request, 'face/login.html')

@csrf_exempt
@login_required
def verify_login(request):
    if request.method != 'POST':
        return HttpResponseBadRequest('Only POST allowed')

    try:
        data = json.loads(request.body)
        input_pin = data.get("pin", "").strip()
        image_data_url = data.get("image")

        # Check against all users
        for user in User.objects.all():
            # Try face match if image is provided
            if image_data_url:
                face_result, msg = match_face(user, image_data_url)
                if face_result:
                    login(request, user)
                    return JsonResponse({'status': 'success', 'message': 'Face matched. Access granted.'})

            # Fallback to PIN check
            if input_pin and check_user_pin(user, input_pin):
                login(request, user)
                return JsonResponse({'status': 'success', 'message': 'PIN matched. Access granted.'})

        return JsonResponse({'status': 'error', 'message': 'Access Denied: Invalid face or PIN'})

    except Exception as e:
        return JsonResponse({'status': 'error', 'message': f'Error: {str(e)}'})

# upload


from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib import messages
from .forms import FileUploadForm
import os

@login_required
def upload_file_view(request):
    form = FileUploadForm()
    folder_files = {}

    user_folder_path = os.path.join(settings.MEDIA_ROOT, request.user.username)
    os.makedirs(user_folder_path, exist_ok=True)  # Create user folder if it doesn't exist

    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            folder_name = form.cleaned_data['folder_name']
            uploaded_file = request.FILES['file']

            # Save file inside user-specific folder
            folder_path = os.path.join(user_folder_path, folder_name)
            os.makedirs(folder_path, exist_ok=True)

            file_path = os.path.join(folder_path, uploaded_file.name)
            with open(file_path, 'wb+') as destination:
                for chunk in uploaded_file.chunks():
                    destination.write(chunk)

            messages.success(request, 'File uploaded successfully!')
            return redirect('upload_file')

    # ✅ Read only the current user's folders & files
    if os.path.exists(user_folder_path):
        for folder in os.listdir(user_folder_path):
            folder_path = os.path.join(user_folder_path, folder)
            if os.path.isdir(folder_path):
                folder_files[folder] = os.listdir(folder_path)

    return render(request, 'face/vault.html', {
        'form': form,
        'folder_files': folder_files,
        'media_url': settings.MEDIA_URL,
        'user_folder': request.user.username,  # for building file links
    })

from django.http import FileResponse, Http404

@login_required
def serve_user_file(request, folder, filename):
    user_folder_path = os.path.join(settings.MEDIA_ROOT, request.user.username, folder)
    file_path = os.path.join(user_folder_path, filename)

    if not os.path.exists(file_path):
        raise Http404("File not found")

    return FileResponse(open(file_path, 'rb'))
