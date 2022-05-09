from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.authtoken.serializers import AuthTokenSerializer
from knox.auth import AuthToken, TokenAuthentication
from .serializers import RegisterSerializer
from rest_framework import status, permissions, request
from knox.views import LoginView
from django.contrib.auth import login

def serialize_user(user):
    return {
        "username": user.username,
        "email": user.email,
        "name": user.first_name,
    }

class LoginAPI(LoginView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request, format=None):
        serializer = AuthTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        login(request, user)
        return super(LoginAPI, self).post(request, format=None)      

@api_view(['POST'])
def register(request):
    serializer = RegisterSerializer(data=request.data)
    if serializer.is_valid(raise_exception=True):
        user = serializer.save()
        _, token = AuthToken.objects.create(user)
        return Response({
            "user_info": serialize_user(user),
            "token": token
        })

@api_view(['GET'])
def get_user(request):
    user = request.user
    if user.is_authenticated:
        return Response({
            'user_info': serialize_user(user)
        })
    return Response({'error_message': 'tidak terautentikasi'}, status.HTTP_401_UNAUTHORIZED)