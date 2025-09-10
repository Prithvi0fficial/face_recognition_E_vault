

import hashlib
import os

PIN_FILE = "data/pin_hash.txt"

def check_pin(input_pin):
    if not os.path.exists(PIN_FILE):
        return False

    hashed_input = hashlib.sha256(input_pin.encode()).hexdigest()
    with open(PIN_FILE, "r") as f:
        stored_hash = f.read().strip()

    return hashed_input == stored_hash




import hashlib
import os
import pickle
import base64
import numpy as np
from PIL import Image
import face_recognition
from io import BytesIO
from django.contrib.auth import get_user_model

User = get_user_model()

def check_user_pin(user, input_pin):
    user_folder = os.path.join('data', user.username)
    pin_file = os.path.join(user_folder, 'pin_hash.txt')
    
    if not os.path.exists(pin_file):
        return False

    with open(pin_file, "r") as f:
        stored_hash = f.read().strip()

    input_hash = hashlib.sha256(input_pin.encode()).hexdigest()
    return stored_hash == input_hash

def match_face(user, image_data_url):
    try:
        face_file = os.path.join('data', user.username, 'face_encoding.pkl')
        if not os.path.exists(face_file):
            return False, "No face registered"

        with open(face_file, 'rb') as f:
            known_encoding = pickle.load(f)

        header, base64_data = image_data_url.split(",", 1)
        image_data = base64.b64decode(base64_data)
        image = Image.open(BytesIO(image_data)).convert('RGB')
        image_np = np.array(image)

        encodings = face_recognition.face_encodings(image_np)
        if not encodings:
            return False, "No face found in image"

        match_result = face_recognition.compare_faces([known_encoding], encodings[0])[0]
        return match_result, "Face match success" if match_result else "Face not matched"
    except Exception as e:
        return False, str(e)
