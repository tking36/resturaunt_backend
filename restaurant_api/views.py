from django.shortcuts import render

from rest_framework import generics
from .serializers import RestaurantSerializer, ReviewSerializer
from .models import Restaurant, Review
from rest_framework.views import APIView
from rest_framework.response import Response
from django.urls import reverse
from rest_framework import status
from django.contrib.auth.models import User
from rest_framework.permissions import IsAuthenticated
from rest_framework.permissions import AllowAny
from django.contrib.auth.forms import UserCreationForm
from rest_framework_simplejwt.tokens import RefreshToken
import json

class RestaurantList(generics.ListCreateAPIView):
    queryset = Restaurant.objects.all().order_by('id') # tell django how to retrieve all objects from the DB, order by id ascending
    serializer_class = RestaurantSerializer # tell django what serializer to use

class RestaurantDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Restaurant.objects.all().order_by('id')
    serializer_class = RestaurantSerializer

class ReviewList(generics.ListCreateAPIView):
    queryset = Review.objects.all().order_by('id')
    serializer_class = ReviewSerializer

class ReviewDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Review.objects.all().order_by('id')
    serializer_class = ReviewSerializer

class HomeView(APIView):
    permission_classes = (IsAuthenticated, )
    def get(self, request):
        content = {'message': 'Welcome to the JWT Auth page using React and Django'}
        return Response(content)

class LogoutView(APIView):
    permission_classes = (IsAuthenticated, )
    def post(self, request):
        print(request)
        print(request.data)
        try:
            refresh_token = request.data['refresh_token']
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        
class SignUpView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, format=None):
            print('data reaching if statement')
            data = json.loads(request.body.decode('utf-8'))
            print(data)
            form = UserCreationForm(data)
            if form.is_valid():
                user = form.save()
                print(user.username)
                return Response({'message': 'User created successfully'}, status=status.HTTP_201_CREATED)
            return Response(form.errors, status=status.HTTP_400_BAD_REQUEST)