import re

from rest_framework import serializers
from rest_framework.serializers import ModelSerializer
from rest_framework_jwt.settings import api_settings

from api.models import User

jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER


class UserModelSerializer(ModelSerializer):
    # 自定义反序列化字段 代表这个字段只参与反序列化  且不会要求这个字段必须与model类映射
    account = serializers.CharField(write_only=True)
    pwd = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ["account", "pwd", "username", "phone", "email"]

        extra_kwargs = {
            "username": {
                "read_only": True,
            },
            "phone": {
                "read_only": True,
            },
            "email": {
                "read_only": True,
            }

        }

    def validate_account(self, value):
        return value

    def validate_pwd(self, value):
        return value

    def validate(self, attrs):
        account = attrs.get("account")
        pwd = attrs.get("pwd")

        # 对于各种登录方式做处理  账号  邮箱  手机号
        if re.match(r'.+@.+', account):
            user_obj = User.objects.filter(email=account).first()
        elif re.match(r'1[3-9][0-9]{9}', account):
            user_obj = User.objects.filter(phone=account).first()
        else:
            user_obj = User.objects.filter(username=account).first()

        # 判断用户是否存在 且用户密码是否正确
        if user_obj and user_obj.check_password(pwd):
            # 签发token
            payload = jwt_payload_handler(user_obj)  # 生成载荷信息
            token = jwt_encode_handler(payload)  # 生成token
            self.token = token
            self.obj = user_obj

        return attrs
