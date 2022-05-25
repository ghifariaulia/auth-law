from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.authtoken.serializers import AuthTokenSerializer
from rest_framework.views import APIView
from django.http import HttpResponse
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
        user_info = super(LoginAPI, self).post(request, format=None)
        serializer = serialize_user(user)
        user_info.data['username'] = serializer['username']
        user_info.data['email'] = serializer['email']
        user_info.data['name'] = serializer['name']
        return Response({'user_info': user_info.data})  

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

class VerifyToken(APIView):
    def post(self, request):
        token = request.headers["Authorization"][6:14]
        try:
            user = AuthToken.objects.get(token_key=token)
            return HttpResponse(user)
        except AttributeError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token salah")
        