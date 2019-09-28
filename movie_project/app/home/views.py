# 前台视图
# coding:utf8
import datetime
import os
from functools import wraps

from sqlalchemy import or_
from werkzeug.security import generate_password_hash,check_password_hash
from flask import render_template, redirect, url_for, flash, session, request
from werkzeug.utils import secure_filename

from app.home.forms import *
from . import home
from app.models import User, Userlog, Comment, Movie, Moviecol, Preview, Tag
import uuid
from app import db,app

# 修改文件名称
def change_filename(filename):
    fileinfo = os.path.splitext(filename)
    # 文件后缀
    filename = datetime.datetime.now().strftime("%Y%m%d%H%M%S") + str(uuid.uuid4().hex) + fileinfo[1]
    return filename


#登录装饰器
def user_login_rep(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for("home.login", next=request.url))
        return f(*args, **kwargs)

    return decorated_function



# 登录
@home.route("/login/",methods=["POST","GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        data = form.data
        # 使用or查询满足一个即可
        user = User.query.filter_by(name=data['name']).first()
        # print('---------')
        # print(user)
        if user == None:
            user = User.query.filter_by(email = data['name']).first()
            if user == None:
                user = User.query.filter_by(phone=data['name']).first()
                print(user)
                if user==None:
                    flash('用户名不存在！','err')
                    return redirect(url_for('home.login'))
        if not user.check_pwd(data['pwd']):
            flash('用户名或密码错误！','err')
            return redirect(url_for('home.login'))
        session['user'] = user.name
        session['user_id'] = user.id
        userlog = Userlog(
            user_id=user.id,
            ip = request.remote_addr
        )
        db.session.add(userlog)
        db.session.commit()
        return redirect(url_for('home.user'))
    return render_template('home/login.html',form=form)

#退出
@home.route("/logout/")
@user_login_rep
def logout():
    session.pop('user',None)
    session.pop('user_id',None)
    return redirect(url_for('home.login'))


# 会员注册
@home.route("/register/",methods=["GET","POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        data = form.data
        user = User(
            name = data['name'],
            email=data['email'],
            phone=data['phone'],
            pwd=generate_password_hash(data['pwd']),
            uuid=uuid.uuid4().hex
        )
        db.session.add(user)
        db.session.commit()
        flash("注册成功",'ok')
    return render_template("home/register.html",form=form)

#会员中心
@home.route("/user/",methods=["GET","POST"])
@user_login_rep
def user():
    form = UserdateilForm()
    # print(form.name.label)
    user = User.query.get(int(session['user_id']))
    form.face.validators=[]
    # print(user.face)
    if request.method=="GET":
        form.name.data = user.name
        form.email.data = user.email
        form.phone.data = user.phone
        form.info.data = user.info
    if form.validate_on_submit():
        data = form.data
        face = secure_filename(form.face.data.filename)
        if not os.path.exists(app.config["FC_DIR"]):  # 文件夹中是否有该文件
            os.makedirs(app.config["FC_DIR"])  # 创建
            os.chmod(app.config["FC_DIR"], "rw")
        user.face = change_filename(face)
        form.face.data.save(app.config["FC_DIR"] + user.face)  # 保存

        # 修改错误时
        name_count = User.query.filter_by(name=data['name']).count()
        if data['name'] != user.name and name_count == 1:
            flash("昵称已存在！",'err')
            return redirect(url_for("home.user"))
        user.name = data['name']

        email_count = User.query.filter_by(email=data['email']).count()
        if data['email'] != user.email and email_count == 1:
            flash("邮箱已存在！",'err')
            return redirect(url_for("home.user"))
        user.email = data['email']

        phone_count = User.query.filter_by(phone=data['phone']).count()
        if data['phone'] != user.phone and phone_count == 1:
            flash("手机已存在！",'err')
            return redirect(url_for("home.user"))
        user.phone = data['phone']

        user.info = data['info']

        db.session.add(user)
        db.session.commit()
        flash("修改成功！",'ok')
        return  redirect(url_for("home.user"))
    return render_template("home/user.html",form=form,user=user)

# 修改密码
@home.route("/pwd/",methods=["GET","POST"])
@user_login_rep
def pwd():
    form = UpdatePwdForm()
    if form.validate_on_submit():
        data = form.data
        # 获取用户
        # username = session["user"]
        # 查询
        user = User.query.filter_by(name=session['user']).first()
        if not user.check_pwd(data["oldpwd"]):
            flash("旧密码错误！",'err')
            return redirect(url_for("home.pwd"))
        # print(session["admin"])
        # 导入哈希加密
        from werkzeug.security import generate_password_hash
        # 密码加密
        user.pwd = generate_password_hash(data["newpwd"])

        db.session.add(user)
        db.session.commit()
        flash("修改密码成功！",'ok')
        return redirect(url_for("home.login"))
    return render_template("home/pwd.html",form=form)

#评论记录
@home.route("/comment/<int:page>/",methods=["GET"])
@user_login_rep
def comment(page=None):
    if page==None:
        page=1
    user_id = session['user_id']
    # print(user_id)
    form = Comment.query.join(
        User
    ).join(
        Movie
    ).filter(
        User.id==user_id,
        Movie.id == Comment.movie_id,
    ).order_by(
        Comment.addtime.desc()
    ).paginate(page=page,per_page=10)
    return render_template("home/comment.html",form=form,page=1)

#会员中心
@home.route("/loginlog/<int:page>/",methods=["GET"])
@user_login_rep
def loginlog(page=None):
    if page==None:
        page=1
    page_data = Userlog.query.filter_by(
        user_id=int(session["user_id"])
    ).order_by(
        Userlog.addtime.desc()
    ).paginate(page=page,per_page=10)
    return render_template("home/loginlog.html",page_data=page_data)

#添加电影收藏
@home.route("/moviecol/add/",methods=["GET"])
@user_login_rep
def moviecol_add():
    uid =request.args.get('uid','')
    mid = request.args.get('mid','')
    moviecol = Moviecol.query.filter_by(
        user_id = int(uid),
        movie_id = int(mid)
    ).count()
    # data = 0
    # print(moviecol)
    if moviecol==1 :
       data = dict(ok=0)
    if moviecol == 0:
        moviecol = Moviecol(
            user_id=int(uid),
            movie_id=int(mid)
        )
        db.session.add(moviecol)
        db.session.commit()
        data =dict(ok=1)
    print(data)
    import json
    return json.dumps(data)

# 删除收藏
@home.route("/moviecol_del/<int:id>/",methods=["GET"])
@user_login_rep
def moviecol_del(id=None):
    print(id)
    moviecol = Moviecol.query.get_or_404(int(id))  # 查询
    print(moviecol)
    db.session.delete(moviecol)
    db.session.commit()
    flash('删除成功','ok')
    return redirect(url_for("home.moviecol", page=1))

# 收藏电影
@home.route("/moviecol/<int:page>/",methods=["GET"])
@user_login_rep
def moviecol(page=None):
    if page == None:
        page = 1
    page_data=Moviecol.query.join(
        User
    ).join(
        Movie
    ).filter(
        User.id == int(session["user_id"]),
        Movie.id == Moviecol.movie_id,
    ).order_by(
        Moviecol.addtime.desc()
    ).paginate(page=page,per_page=10)
    return render_template("home/moviecol.html",page_data=page_data)

# 主页
@home.route("/<int:page>/",methods=["GET"])
# @user_login_rep
def index(page=None):
    if page == None:
        page=1
    tags = Tag.query.all()
    tid = request.args.get("tid",0)
    # 标签
    page_data=Movie.query
    if int(tid) !=0:
        page_data=page_data.filter_by(tag_id=int(tid))

    # 星级
    star = request.args.get("star",0)
    if int(star) != 0:
        page_data=page_data.filter_by(star=int(star))

    # 时间
    time = request.args.get("time",0)
    if int(time) != 0:
        if int(time) == 1:
            page_data = page_data.order_by(
                Movie.addtime.desc()
            )
        else:
            page_data =page_data.order_by(
                Movie.addtime.asc()
            )
    # 播放量
    pm = request.args.get("pm",0)
    if int(pm) != 0:
        if int(pm) == 1:
            page_data = page_data.order_by(
                Movie.playnum.desc()
            )
        else:
            page_data = page_data.order_by(
                Movie.playnum.asc()
            )
    # 评论数量
    cm = request.args.get("cm",0)
    if int(cm) != 0:
        if int(cm) == 1:
            page_data = page_data.order_by(
                Movie.commentnum.desc()
            )
        else:
            page_data = page_data.order_by(
                Movie.commentnum.asc()
            )
    page = request.args.get('page',1)
    page_data=page_data.paginate(page=page,per_page=10)
    p = dict(
        tid=tid,
        star=star,
        time=time,
        pm=pm,
        cm=cm,
    )
    return render_template("home/index.html",tags=tags,p=p,page_data=page_data)

#上映预告
@home.route("/animation/")
@user_login_rep
def animation():
    data = Preview.query.all()
    # print(data)
    return render_template("home/animation.html",data=data)

# 搜索
@home.route("/search/<int:page>/")
@user_login_rep
def search(page=None):
    if page==None:
        page=1
    key = request.args.get('key','')
    # 数量
    movie_count = Movie.query.filter(
        Movie.title.ilike('%'+key+'%')
    ).count()
    page_data = Movie.query.filter(
        Movie.title.ilike('%'+key+'%')
    ).order_by(
            Movie.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("home/search.html",key=key,page_data=page_data,movie_count=movie_count)

#播放
@home.route("/play/<int:id>/<int:page>/",methods=["GET","POST"])
@user_login_rep
def play(id=None,page=None):
    if page == None:
        page=1
    # 获取评论
    form = CommentForm()
    if 'user' in session and form.validate_on_submit():
        data = form.data
        print(data)
        #保存评论
        com = Comment(
            movie_id=int(id),
            user_id=int(session['user_id']),
            content=data['comment']
        )
        db.session.add(com)
        db.session.commit()
        flash('评论成功','ok')
        return redirect(url_for('home.play',id=id,page=1))
    name = session['user']
    movie = Movie.query.join(Tag).filter(
        Tag.id == Movie.tag_id,
        Movie.id ==int(id)
    ).first_or_404()
    # 评论
    comment = Comment.query.join(Movie).join(User).filter(
        Comment.user_id==User.id,
        Comment.movie_id == Movie.id,
        Movie.id==int(id),

    ).paginate(page=page,per_page=10)
    # 评论数量
    comment_count = Comment.query.join(Movie).join(User).filter(
        Comment.user_id == User.id,
        Comment.movie_id == Movie.id,
        Movie.id == int(id),

    ).count()
    # print(comment)
    return render_template("home/play.html",form=form,
                           movie=movie,name=name,
                           comment=comment,comment_count=comment_count)
