
from django.contrib import admin
from django.urls import path
from .views import *


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/oauth/initiate/', initiate_oauth, name='initiate_oauth'),
    path('api/callback/', oauth_callback, name='oauth_callback'),
    path('api/jwks/', jwks, name='jwks'),
    path('api/get_patient', get_patient, name='get_patient'),
    path('api/clinical-notes/', fetch_clinical_notes, name='clinical_notes'),
    path('api/call-fhir-export/', call_fhir_export_api, name='call_fhir_export'),
    path('api/login/', advancedmd_login, name='advancedmd_login')

]
