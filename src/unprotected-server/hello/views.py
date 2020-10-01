from django.shortcuts import render
from django.http import JsonResponse

def index(request):
    return JsonResponse({"message": "Hello, World!"})

def not_found(request, exception):
    return JsonResponse({}, status = 404)
