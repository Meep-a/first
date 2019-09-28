# 表单
# coding:utf8

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, TextAreaField
from wtforms.validators import DataRequired, Email, Regexp, EqualTo, ValidationError

from app.models import User


class RegisterForm(FlaskForm):
    '''
    用户注册表单
    '''
    # 名称
    name = StringField(
        label="昵称",
        validators=[
            DataRequired('请输入昵称！')
        ],
        description='昵称',
        render_kw={
            'id': "input_name",
            'class': "form-control input-lg",
            'placeholder': "请输入昵称!"
        }
    )
    # 邮箱
    email = StringField(
        label='邮箱',
        validators=[
            DataRequired('请输入邮箱！'),
            Email('邮箱格式不正确！')
        ],
        description='邮箱',
        render_kw={
            'id': "input_email",
            'class': "form-control input-lg",
            'placeholder': "请输入邮箱！"
        }
    )
    # 手机
    phone = StringField(
        label='手机',
        validators=[
            DataRequired('请输入手机！'),
            Regexp("1[3589]\d{9}", message="手机格式不正确！")
        ],
        description='手机',
        render_kw={
            'id': "input_phone",
            'class': "form-control input-lg",
            'placeholder': "请输入手机！"
        }
    )
    pwd = PasswordField(
        label="密码",
        validators=[
            DataRequired('请输入密码！')
        ],
        description="密码",
        render_kw={
            'id': "input_password",
            'class': "form-control input-lg",
            'placeholder': "请输入密码！",
            # 'required': "required",
        }

    )
    repwd = PasswordField(
        label="密码",
        validators=[
            DataRequired('请输入密码！'),
            EqualTo('pwd', message="两次密码不一致！")
        ],
        description="密码",
        render_kw={
            'id': "input_repassword",
            'class': "form-control input-lg",
            'placeholder': "请输入密码！",
            # 'required': "required",
        }
    )
    submit = SubmitField(
        '注册',
        render_kw={
            "class": "btn btn-lg btn-success btn-block",
        }
    )

    # 用户名验证
    def validata_name(self, field):
        name = field.data
        user = User.query.filter_by(
            name=name
        ).count()
        if user == 1:
            raise ValidationError("昵称已存在！")

    # 邮箱验证
    def validata_email(self, field):
        email = field.data
        user = User.query.filter_by(
            email=email
        ).count()
        if user == 1:
            raise ValidationError("邮箱已存在！")

    def validata_phone(self, field):
        phone = field.data
        user = User.query.filter_by(
            phone=phone
        ).count()
        if user == 1:
            raise ValidationError("手机已存在！")


class LoginForm(FlaskForm):
    # 名称
    name = StringField(
        label="账号/手机/邮箱",
        validators=[
            DataRequired('请输入账号！')
        ],
        description='账号',
        render_kw={
            'id': "input_name",
            'class': "form-control input-lg",
            'placeholder': "请输入账号!"
        }
    )
    pwd = PasswordField(
        label="密码",
        validators=[
            DataRequired('请输入密码！'),
            # EqualTo('pwd', message="两次密码不一致！")
        ],
        description="密码",
        render_kw={
            'id': "input_repassword",
            'class': "form-control input-lg",
            'placeholder': "请输入密码！",
            # 'required': "required",
        }
    )
    submit = SubmitField(
        '登录',
        render_kw={
            "class": "btn btn-lg btn-success btn-block",
        }
    )


class UserdateilForm(FlaskForm):
    # 名称
    name = StringField(
        label="昵称",
        validators=[
            DataRequired('请输入昵称！')
        ],
        description='昵称',
        render_kw={
            'id': "input_name",
            'class': "form-control input-lg",
            'placeholder': "请输入昵称!"
        }
    )
    # 邮箱
    email = StringField(
        label='邮箱',
        validators=[
            DataRequired('请输入邮箱！'),
            Email('邮箱格式不正确！')
        ],
        description='邮箱',
        render_kw={
            'id': "input_email",
            'class': "form-control input-lg",
            'placeholder': "请输入邮箱！"
        }
    )
    # 手机
    phone = StringField(
        label='手机',
        validators=[
            DataRequired('请输入手机！'),
            Regexp("1[3589]\d{9}", message="手机格式不正确！")
        ],
        description='手机',
        render_kw={
            'id': "input_phone",
            'class': "form-control input-lg",
            'placeholder': "请输入手机！"
        }
    )
    face = FileField(
        label='头像',
        validators=[
            DataRequired('请上传头像！'),
        ],
        description="头像"
    )
    info = TextAreaField(
        label="简介",
        validators=[
            DataRequired('请输入简介！')
        ],
        description="简介",
        render_kw={
            'class': "form-control",
            'rows': "10",
            'id': "input_info"
        }
    )
    submit = SubmitField(
        '保存修改',
        render_kw={
            "class": "btn btn-success",
        }
    )

class UpdatePwdForm(FlaskForm):
    oldpwd = PasswordField(
        label="旧密码",
        validators=[
            DataRequired('请输入旧密码！'),
            # EqualTo('pwd', message="两次密码不一致！")
        ],
        description="旧密码",
        render_kw={
            'id': "input_oldpwd",
            'class': "form-control",
            'placeholder': "请输入旧密码！",
            # 'required': "required",
        }
    )
    newpwd = PasswordField(
        label="新密码",
        validators=[
            DataRequired('请输入新密码！'),
            # EqualTo('pwd', message="两次密码不一致！")
        ],
        description="新密码",
        render_kw={
            'id': "input_newpwd",
            'class': "form-control",
            'placeholder': "请输入新密码！",
            # 'required': "required",
        }
    )

    submit = SubmitField(
        '修改密码',
        render_kw={
            "class": "btn btn-success",
        }
    )

    # # 旧密码验证
    # def validate_old_pwd(self, field):
    #     from flask import session
    #     old_pwd = field.data
    #     name = session["user"]
    #     user = User.query.filter_by(name=name).first()
    #     if not user.check_pwd(old_pwd):
    #         raise ValidationError("旧密码错误！",'err')

class CommentForm(FlaskForm):
    # 名称
    comment = TextAreaField(
        label="提交评论",
        validators=[
            DataRequired('请输入评论！')
        ],
        description='评论',
        render_kw={
            'id': "input_content",
            'placeholder': "请输入评论!"
        }
    )
    submit = SubmitField(
        '提交评论',
        render_kw={
            "class": "btn btn-success",
        }
    )