import base64
from datetime import datetime, timedelta
import json
import time

from django.forms import model_to_dict
import jwt
import secrets
from django.shortcuts import redirect, render
from django.db.models import Q
from django.http import HttpResponse, JsonResponse
from django.conf import settings
import requests
from django.http import HttpResponse, JsonResponse
from requests.auth import HTTPBasicAuth
from .utils import generate_code_verifier, generate_code_challenge, create_jwt, decode_jwt, generate_kid_from_key, load_key
import base64
import os
import uuid
import xml.etree.ElementTree as ET
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.utils import timezone


def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def jwks(request):
    with open("./keys/public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    numbers = public_key.public_numbers()
    modulus = numbers.n
    exponent = numbers.e

    modulus_bytes = modulus.to_bytes(
        (modulus.bit_length() + 7) // 8, byteorder='big')
    exponent_bytes = exponent.to_bytes(
        (exponent.bit_length() + 7) // 8, byteorder='big')
    modulus_base64url = base64url_encode(modulus_bytes)
    exponent_base64url = base64url_encode(exponent_bytes)

    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": generate_kid_from_key('./keys/private_key.pem'),
                "use": "sig",
                "alg": "RS384",
                "n": modulus_base64url,
                "e": exponent_base64url
            }
        ]
    }

    return JsonResponse(jwks)


def generate_jwt(client_id):
    payload = {
        "iss": client_id,
        "sub": client_id,
        "aud": "https://providerapi.advancedmd.com/v1/oauth2/token",
        "exp": int((datetime.now() + timedelta(seconds=3600)).timestamp()),
        "jti": str(uuid.uuid4())
    }

    with open('./keys/private_key.pem', 'r') as key_file:
        private_key = key_file.read()

    headers = {
        "typ": "JWT",
        "alg": "RS384",
        "kid": generate_kid_from_key('./keys/private_key.pem')
    }

    token = jwt.encode(payload, private_key,
                       algorithm='RS384', headers=headers)

    return token


def oauth_callback(request):
    state = request.GET.get('state')
    code = request.GET.get('code')
    stored_state = request.session.get('oauth_state')
    if state != stored_state:
        return HttpResponse("Invalid State", status=400)
    print(settings.ADVANCEDMD_SINGLEFHIR_REDIRECT_URI)
    token_url = "https://providerapi.advancedmd.com/v1/oauth2/token"
    token_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'scope': 'openid launch/patient openid fhirUser patient/*.read',
        'redirect_uri': settings.ADVANCEDMD_SINGLEFHIR_REDIRECT_URI,
        'client_id': settings.ADVANCEDMD_SINGLEFHIR_CLIENT_ID,
        'client_secret': settings.ADVANCEDMD_SINGLEFHIR_CLIENT_SECRET
    }

    response = requests.post(token_url, data=token_data)
    response_data = response.json()

    if response.status_code == 200:
        access_token = response_data.get('access_token')
        print(access_token)
        return HttpResponse(f"Access Token: {access_token}")
    else:
        error_description = response_data.get(
            'error_description', 'Unknown error')
        return HttpResponse(f"Error: {error_description}", status=response.status_code)


def initiate_oauth(request):
    state = secrets.token_urlsafe(32)

    request.session['oauth_state'] = state

    oauth_url = (
        f"https://providerapi.advancedmd.com/v1/oauth2/authorize?"
        f"response_type=id_token&"
        f"scope=launch/patient openid fhirUser offline_access patient/Medication.read patient/AllergyIntolerance.read patient/CarePlan.read patient/CareTeam.read patient/Condition.read patient/Device.read patient/DiagnosticReport.read patient/DocumentReference.read patient/Encounter.read patient/Goal.read patient/Immunization.read patient/Location.read patient/MedicationRequest.read patient/Observation.read patient/Organization.read patient/Patient.read patient/Practitioner.read patient/Procedure.read patient/Provenance.read patient/PractitionerRole.read&"
        f"client_id=KzKJpA7GpbHhZzQZPjpqV77tkafmUwOA&"
        f"redirect_uri=https://broots-mea.dataterrain-dev.net/api/callback&"
        f"state={state}"
    )

    return redirect(oauth_url)


def get_oauth2_token():
    client_id = 'C8uUIqvc54Z8vUAsKGbDsv2Mm6lhDLWk'
    jwt_token = generate_jwt(client_id)

    try:
        token_url = 'https://providerapi.advancedmd.com/v1/oauth2/token'

        payload = {
            'client_assertion': jwt_token,
            'client_assertion_type': "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            'scope': "system/*.read",
            'grant_type': "client_credentials",
            'username': "MEA",
            'password': "TP!9=a_JztVt",
            'officekey': "129238"
        }

        response = requests.post(token_url, data=payload, headers={
            'Content-Type': 'application/x-www-form-urlencoded'
        })

        json_data = response.json()
        print(json_data)
        token = json_data['access_token']

        return token

    except json.JSONDecodeError:
        return ('Invalid JSON')
    except Exception as e:
        return (e)


def call_fhir_export_api(request):

    endpoint = "https://providerapi.advancedmd.com/v1/r4/Group/129238/$export"

    bearer_token = get_oauth2_token()
    headers = {
        'prefer': "respond-async",
        'OfficeKey': "129238",
        'Authorization': "Bearer {bearer_token}"
    }
    print(bearer_token)
    try:

        response = requests.get(endpoint, headers=headers)
        json_data = response.json()
        print(json_data)
        if response.status_code == 200:
            return JsonResponse({
                'message': 'Export request accepted',
                'status': response.status_code,
                'content-location': response.headers.get('Content-Location')
            })
        elif response.status_code == 400:
            return JsonResponse({
                'message': 'Bad request',
                'status': response.status_code,
                'error': response.json()
            })
        else:

            return JsonResponse({
                'message': 'An unexpected error occurred',
                'status': response.status_code,
                'error': response.text
            })
    except requests.RequestException as e:

        return JsonResponse({
            'message': 'Request failed',
            'error': str(e)
        }, status=500)


def advancedmd_login(request):
    if request.method == 'GET':
        username = settings.ADVANCEDMD_USERNAME
        password = settings.ADVANCEDMD_PASSWORD
        officecode = settings.ADVANCEDMD_OFFICEKEY
        appname = "TEMP"  # Replace with your actual app name

        # Step 1: Send initial login request
        msgtime = timezone.now().strftime("%m/%d/%Y %I:%M:%S %p")
        xml_request = f"""<ppmdmsg action="login"
            class="login"
            msgtime="{msgtime}"
            username="{username}"
            psw="{password}"
            officecode="{officecode}"
            appname="{appname}"/>"""

        initial_url = "https://partnerlogin.advancedmd.com/practicemanager/xmlrpc/processrequest.aspx"

        try:
            response = requests.post(initial_url, data=xml_request, headers={
                                     'Content-Type': 'text/xml'})
            response.raise_for_status()
            print("Response Content:", response.content)

            root = ET.fromstring(response.content)
            results = root.find('Results')

            success = results.get('success')
            if success == "0":

                usercontext = results.find('usercontext')
                redirect_url = usercontext.get(
                    'webserver') + "/xmlrpc/processrequest.aspx"

                redirect_response = requests.post(redirect_url, data=xml_request, headers={
                                                  'Content-Type': 'text/xml'})
                redirect_response.raise_for_status()

                print("Redirect Response Content:", redirect_response.content)

                redirect_root = ET.fromstring(redirect_response.content)
                redirect_results = redirect_root.find('Results')

                redirect_success = redirect_results.get('success')

                if redirect_success == "1":

                    security_token = redirect_results.find('usercontext').text
                    webserver = usercontext.get('webserver')

                    request.session['security_token'] = security_token
                    request.session['webserver'] = webserver

                    return JsonResponse({"status": "success:"+redirect_url, "security_token": security_token})

                else:
                    return JsonResponse({"status": "error", "message": "Redirect login failed"})

            else:
                return JsonResponse({"status": "error", "message": "Initial login failed"})

        except requests.exceptions.RequestException as e:
            return JsonResponse({"status": "error", "message": f"Request failed: {str(e)}"})
        except ET.ParseError:
            return JsonResponse({"status": "error", "message": "Failed to parse XML response."})

    return JsonResponse({"status": "error", "message": "Invalid request method"})


def fetch_clinical_notes(request):

    production_url = 'https://providerapi.advancedmd.com/ehr-api/api-101/TEMP/clinicalnotes/notes'
    app_name = 'TEMP'
    token = '9d949606-7f46-427f-9b1a-6540e5e4d003'

    headers = {
        'appname': app_name,
        'Authorization': f'Bearer {token}',
    }

    try:

        response = requests.get(production_url, headers=headers)
        response.raise_for_status()

        return JsonResponse(response.json(), status=response.status_code)

    except requests.exceptions.RequestException as e:

        return JsonResponse({'error': str(e)}, status=500)


def get_patient(request):

    bearer_token = settings.ADVANCEDMD_SINGLEFHIR_ACCESS_TOKEN
    url = f"https://providerapi.advancedmd.com/v1/r4/Patient"

    headers = {
        'Authorization': f'Bearer ' + bearer_token,
        'Content-Type': 'application/json',
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        json_data = response.json()
        return JsonResponse(json_data)
    else:
        response.raise_for_status()
        return JsonResponse('Error')
