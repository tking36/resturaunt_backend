from django.urls import path
from . import views

urlpatterns = [
    path('api/restaurants', views.RestaurantList.as_view(), name='restaurant_list'), # api/restaurants will be routed to the ContactList view for handling
    path('api/restaurants/<int:pk>', views.RestaurantDetail.as_view(), name='restaurant_detail'), # api/restaurants will be routed to the RestaurantDetail view for handling
    path('api/reviews', views.ReviewList.as_view(), name='review_list'),
    path('api/reviews/<int:pk>', views.ReviewDetail.as_view(), name='review_detail'),
    path('home/', views.HomeView.as_view(), name='home'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('signup/', views.SignUpView.as_view(), name='signup'),
]