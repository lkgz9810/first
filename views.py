import datetime
import json
import logging
import os
from pathlib import Path
import shutil

import jwt
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.http import (HttpResponse, HttpResponseBadRequest,
                         HttpResponseForbidden, HttpResponseNotFound)
from django.utils import timezone
from django.views import View
from django.views.generic import TemplateView

logger = logging.getLogger(__file__)

class HttpResponseUnauthorized(HttpResponse):
    status_code = 401


class Index(TemplateView):
    template_name = 'index.html'
    

class Login(View):
    def post(self, request):
        logging.info(f"Login POST {request.body}")
        encoding = request.POST.get('_encoding', 'UTF-8')
        try:
            body = request.body.decode(encoding)
        except UnicodeDecodeError:
            return HttpResponseBadRequest(f"Could not decode request with encoding: {encoding}. Use UTF-8 or pass a desired encoding along with the request headers.")
    
        try:
            credentials = json.loads(body)
            if not sorted(credentials.keys()) == ['password', 'username']:
                raise ValueError()  # Will result in the HttpResponseBadRequest in the try/catch
        except Exception:  # noqa
            return HttpResponseBadRequest(f"Malformed request body")

        try:
            with open(os.path.join('/data', credentials['username'].lower(), '.password'), 'r') as f:
                assert credentials['password'] in f.read()
        except Exception:
            return HttpResponseForbidden(f"Login credentials are incorrect")

        encoded_jwt = jwt.encode({'username': credentials['username'],
                                  'iat': timezone.now(),
                                  'exp': timezone.now() + datetime.timedelta(hours=48)},
                                 settings.SECRET_KEY,
                                 algorithm='HS256')

        return HttpResponse(encoded_jwt)
    
class Register(View):
    def post(self, request):
        logging.info(f"Register POST {request.body}")
        encoding = request.POST.get('_encoding', 'UTF-8')
        try:
            body = request.body.decode(encoding)
        except UnicodeDecodeError:
            return HttpResponseBadRequest(f"Could not decode request with encoding: {encoding}. Use UTF-8 or pass a desired encoding along with the request headers.")
    
        try:
            credentials = json.loads(body)
            if not sorted(credentials.keys()) == ['password', 'username']:
                raise ValueError()  # Will result in the HttpResponseBadRequest in the try/catch
        except Exception:  # noqa
            return HttpResponseBadRequest(f"Malformed request body")

        # Time to see if this user exists
        if os.path.exists(os.path.join('/data', credentials['username'].lower())):
            return HttpResponseForbidden("User already exists")
        
        try:
            os.makedirs(os.path.join('/data', credentials['username'].lower()))
            with open(os.path.join('/data', credentials['username'].lower(), '.password'), 'w') as f:
                f.write(credentials['password'])

        except Exception:
            return HttpResponseForbidden(f"Something went wrong")

        encoded_jwt = jwt.encode({'username': credentials['username'],
                                  'iat': timezone.now(),
                                  'exp': timezone.now() + datetime.timedelta(hours=48)},
                                 settings.SECRET_KEY,
                                 algorithm='HS256')

        return HttpResponse(encoded_jwt)
    
class Leave(View):
    def delete(self, request, username):
        logging.info(f"Leave DELETE {request.body}")
        
        token = request.headers.get('Authorization')

        try:
            unpacked_token = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
            assert unpacked_token['username'] == username
        except (jwt.exceptions.DecodeError, AssertionError):
            return  HttpResponseUnauthorized("Invalid token")

        user_path = Path('/data').joinpath(username.lower())
        logging.info(f"delting {user_path}")

        if not os.path.exists(user_path):
            return HttpResponseNotFound("User does not exists")
        
        shutil.rmtree(user_path)

        return HttpResponse('Done')
    
class Passwords(View):
    def get(self, request, username):
        logging.info(f"Passwords GET for {username}")

        user_path = f'/data/{username.lower()}'
        if not os.path.exists(user_path):
            return HttpResponseNotFound("User does not exists")
        
        passwords = []
        for p in [f for f in os.listdir(user_path) if f != '.password']:
            with open(os.path.join(user_path, p)) as f:
                passwords.append(f.read())

        return HttpResponse(json.dumps(passwords))

    def post(self, request, username):
        logging.info(f"Passwords POST for {username}")

        token = request.headers.get('Authorization')

        encoding = request.POST.get('_encoding', 'UTF-8')
        try:
            body = request.body.decode(encoding)
        except UnicodeDecodeError:
            return HttpResponseBadRequest(f"Could not decode request with encoding: {encoding}. Use UTF-8 or pass a desired encoding along with the request headers.")

        logging.info(f"A")
        try:
            unpacked_token = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
        except (jwt.exceptions.DecodeError, AssertionError):
            return  HttpResponseUnauthorized("Invalid token")

        logging.info(f"B")
        user_path = f'/data/{username.lower()}'
        if not os.path.exists(user_path):
            return HttpResponseNotFound("User does not exists")
        
        logging.info(f"C")
        data = json.loads(body)

        logging.info(f"D")
        edit = os.path.exists(f"{user_path}/{data['name']}")

        logging.info(f"E exists {user_path}/{data['name']}")
        try:
            with open(f"{user_path}/{data['name']}", 'w') as f:
                logging.info(f"F")
                f.write(data['payload'])
        except Exception as e:
            logging.error(f'{e}')
            return HttpResponseForbidden("Unable to add password")

        logging.info(f"G")
        r = HttpResponse('Done writing passsword')
        r.status_code = 200 if edit else 201
        return r

    def delete(self, request, username):
        logging.info(f"Passwords DELETE for {username}")

        token = request.headers.get('Authorization')

        encoding = request.POST.get('_encoding', 'UTF-8')
        try:
            body = request.body.decode(encoding)
        except UnicodeDecodeError:
            return HttpResponseBadRequest(f"Could not decode request with encoding: {encoding}. Use UTF-8 or pass a desired encoding along with the request headers.")

        try:
            unpacked_token = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
            assert unpacked_token['username'] == username
        except (jwt.exceptions.DecodeError, AssertionError):
            return  HttpResponseUnauthorized("Invalid token")

        user_path = os.path.join('/data', username.lower())

        if not os.path.exists(user_path):
            return HttpResponseNotFound("User does not exists")
        
        data = json.loads(body)

        try:
            target_path = Path(user_path).joinpath(data['name']).resolve().relative_to(Path('/data/').resolve())
        except ValueError:
            return HttpResponseForbidden("Only destroy things you own.")
        os.remove(Path('/data').joinpath(target_path));

        return HttpResponse('done')
