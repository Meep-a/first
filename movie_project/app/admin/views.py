# coding:utf8
import datetime
import os
import uuid
from functools import wraps
from flask import render_template, redirect, url_for, flash, session, request,abort
from werkzeug.utils import secure_filename
from app import db, app
from app.admin.forms import *
from app.models import Admin, Tag, Movie, Preview, User, Comment, \
    Moviecol, Oplog, Adminlog, Userlog, Auth, Role
from . import admin  # 导入app


# 上下应用处理器，充当全局变量，可以展现在模板中
@admin.context_processor
def tpl_extra():
    data = dict(
        online_time=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    return data


# 登录装饰器
def admin_login_rep(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin' not in session:
            return redirect(url_for("admin.login", next=request.url))
        return f(*args, **kwargs)

    return decorated_function


#权限控制装饰器
def admin_auth(f):
    @wraps(f)
    def decorated_function(*args,**kwargs):
        admin=Admin.query.join(
            Role
        ).filter(
          Role.id==Admin.role_id,
          Admin.id==session["admin_id"]
        ).first()
        auths = admin.role.auths
        auths = list(map( lambda v :int(v),auths.split(",")))
        auth_list = Auth.query.all()
        urls = [v.url for v in auth_list for val in auths if val ==v.id]
        rule =request.url_rule
        if str(rule) not in urls:
            abort(404)
        return f(*args,**kwargs)
    return decorated_function

# 修改文件名称
def change_filename(filename):
    fileinfo = os.path.splitext(filename)
    # 文件后缀
    filename = datetime.datetime.now().strftime("%Y%m%d%H%M%S") + str(uuid.uuid4().hex) + fileinfo[1]
    return filename


@admin.route("/")
@admin_login_rep
# @admin_auth
def index():
    return render_template("admin/index.html")


# 登录
@admin.route("login", methods=['GET', 'POST'])
# @admin_login_rep
def login():
    form = LoginForm()
    if form.validate_on_submit():
        data = form.data
        # print(data)
        # print(data['account'])
        admin = Admin.query.filter_by(name=data['account']).first()
        # print(admin)
        if not admin.check_pwd(data['pwd']):
            flash("密码错误！", 'err')
            return redirect(url_for('admin.login'))
        session['admin'] = data['account']
        session["admin_id"] = admin.id
        # 管理员登录日志保存
        adminlog = Adminlog(
            admin_id=admin.id,
            ip=request.remote_addr,
        )
        db.session.add(adminlog)
        db.session.commit()

        return redirect(request.args.get('next') or url_for('admin.index'))
    return render_template("admin/login.html", form=form)


# 退出登录
@admin.route("logout")
@admin_login_rep
def logout():
    session.pop('admin', None)  # 退出删除账号
    session.pop('admin_id', None)
    return redirect(url_for("admin.login"))


# 修改密码
@admin.route("/pwd/", methods=["GET", "POST"])
@admin_login_rep
def pwd():
    form = PwdForm()
    if form.validate_on_submit():
        data = form.data  # 获取数据
        # 查询                             当前用户名
        admin = Admin.query.filter_by(name=session['admin']).first()
        # print(session["admin"])
        # 导入哈希加密
        from werkzeug.security import generate_password_hash
        # 密码加密
        admin.pwd = generate_password_hash(data["new_pwd"])
        db.session.add(admin)
        db.session.commit()
        oplog = Oplog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason="修改密码"
        )
        db.session.add(oplog)
        db.session.commit()
        flash("修改密码成功！", 'ok')
        return redirect(url_for('admin.logout'))
    return render_template("admin/pwd.html", form=form)


# 添加标签
@admin.route("/tag/add", methods=['GET', 'POST'])
@admin_login_rep
# @admin_auth
def tag_add():
    form = TagForm()
    if form.validate_on_submit():
        data = form.data
        tag = Tag.query.filter_by(name=data['name']).count()  # 查询数据条数
        if tag == 1:
            flash('名称已存在！', 'err')
            return redirect(url_for('admin.tag_add'))
        tag = Tag(
            name=data['name']
        )
        db.session.add(tag)  # 添加
        db.session.commit()  # 保存
        flash('添加标签成功', 'ok')
        oplog = Oplog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason="添加标签%s" % data["name"]
        )
        db.session.add(oplog)
        db.session.commit()
        return redirect(url_for('admin.tag_add'))
    return render_template("admin/tag_add.html", form=form)


# 标签管理
@admin.route("/tag/list/<int:page>", methods=["GET"])
@admin_login_rep
# @admin_auth
def tag_list(page=None):
    if page is None:
        page = 1
    page_data = Tag.query.order_by(
        Tag.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/tag_list.html", page_data=page_data)


# 标签删除
@admin.route("/tag/del/<int:id>", methods=["GET"])
@admin_login_rep
# @admin_auth
def tag_del(id=None):
    tag = Tag.query.filter_by(id=id).first_or_404()
    # 保存操作
    print(tag.name)
    oplog = Oplog(
        admin_id=session['admin_id'],
        ip=request.remote_addr,
        reason="删除标签%s" % tag.name
    )
    db.session.add(oplog)
    db.session.commit()
    # 删除
    db.session.delete(tag)
    db.session.commit()

    flash("删除标签成功！", 'ok')
    return redirect(url_for("admin.tag_list", page=1))


# 编辑标签
@admin.route("/tag/edit/<int:id>", methods=['GET', 'POST'])
@admin_login_rep
# @admin_auth
def tag_edit(id=None):
    form = TagForm()
    tag = Tag.query.get_or_404(id)
    if form.validate_on_submit():
        data = form.data
        tag_count = Tag.query.filter_by(name=data['name']).count()  # 查询数据条数
        if tag.name == data['name'] and tag_count == 1:
            flash('名称已存在！', 'err')
            return redirect(url_for('admin.tag_add', id=id))
        tag.name = data['name']
        db.session.add(tag)  # 添加
        db.session.commit()  # 保存
        oplog = Oplog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason="修改标签%s" % data["name"]
        )
        db.session.add(oplog)
        db.session.commit()
        flash('修改标签成功', 'ok')
        return redirect(url_for('admin.tag_edit', id=id))
    return render_template("admin/tag_edit.html", form=form, tag=tag)


# 添加电影
@admin.route("/movie/add", methods=["GET", "POST"])
@admin_login_rep
# @admin_auth
def movie_add():
    form = MovieForm()
    if form.validate_on_submit():
        data = form.data
        file_url = secure_filename(form.url.data.filename)
        # print(file_url)
        file_logo = secure_filename(form.logo.data.filename)
        if not os.path.exists(app.config["UP_DIR"]):  # 文件夹中是否有该文件
            os.makedirs(app.config["UP_DIR"])  # 创建
            os.chmod(app.config["UP_DIR"], "rw")
        url = change_filename(file_url)
        # print(url)
        logo = change_filename(file_logo)
        form.url.data.save(app.config["UP_DIR"] + url)  # 保存
        form.logo.data.save(app.config["UP_DIR"] + logo)  # 保存
        movie = Movie(
            title=data["title"],
            url=url,
            info=data["info"],
            logo=logo,
            star=int(data["star"]),
            playnum=0,
            commentnum=0,
            tag_id=int(data["tag_id"]),
            area=data["area"],
            release_time=data["release_time"],
            length=data["length"]
        )
        db.session.add(movie)
        db.session.commit()
        # 保存记录
        oplog = Oplog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason="添加电影%s" % movie.title
        )
        db.session.add(oplog)
        db.session.commit()
        # print(movie.url)
        flash("添加电影成功", "ok")
        return redirect(url_for("admin.movie_add"))
    return render_template("admin/movie_add.html", form=form)


# 电影列表
@admin.route("/movie/list/<int:page>/", methods=["GET"])
@admin_login_rep
# @admin_auth
def movie_list(page=None):
    if page is None:
        page = 1
    # 查询
    page_data = Movie.query.join(Tag).filter(
        Tag.id == Movie.tag_id
    ).order_by(
        Movie.addtime.desc()
    ).paginate(page=page, per_page=10)
    # print(page_data)
    return render_template("admin/movie_list.html", page_data=page_data)


# 删除电影
@admin.route("/movie/del/<int:id>/", methods=["GET", "POST"])
@admin_login_rep
def movie_del(id=None):
    # print(id)
    movie = Movie.query.filter_by(id=id).first_or_404()  # 查询
    # 保存记录
    oplog = Oplog(
        admin_id=session['admin_id'],
        ip=request.remote_addr,
        reason="删除电影%s" % movie.title
    )
    db.session.add(oplog)
    db.session.commit()
    # print(movie)
    db.session.delete(movie)  # 删除
    db.session.commit()
    flash("删除电影成功", "ok")
    return redirect(url_for("admin.movie_list", page=1))


# 电影修改
@admin.route("/movie/edit/<int:id>/", methods=["GET", "POST"])
@admin_login_rep
def movie_edit(id=None):
    form = MovieForm()
    form.url.validators = []
    movie = Movie.query.get_or_404(int(id))
    if request.method == "GET":
        form.info.data = movie.info
        form.star.data = movie.star
        form.tag_id.data = movie.tag_id
    if form.validate_on_submit():
        data = form.data
        movie_count = Movie.query.filter_by(title=data["title"]).count()
        if movie_count == 1 and movie.title == data["title"]:
            flash("片名已经存在！", "err")
            return redirect(url_for("admin.movie_edit", id=id))
        if not os.path.exists(app.config["UP_DIR"]):  # 文件夹中是否有该文件
            os.makedirs(app.config["UP_DIR"])  # 创建
            os.chmod(app.config["UP_DIR"], "rw")
        if form.url.data.filename != "":
            file_url = secure_filename(form.url.data.filename)
            movie.url = change_filename(file_url)
            form.url.data.save(app.config["UP_DIR"] + movie.url)  # 保存

        if form.logo.data.filename != "":
            file_logo = secure_filename(form.logo.data.filename)
            movie.logo = change_filename(file_logo)
            form.logo.data.save(app.config["UP_DIR"] + movie.logo)  # 保存

        movie.star = data["star"]
        movie.tag_id = data["tag_id"]
        movie.info = data["info"]
        movie.title = data["title"]
        movie.area = data["area"]
        movie.length = data["length"]
        movie.release_time = data["release_time"]
        # 保存记录
        oplog = Oplog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason="修改电影%s" % movie.title
        )
        db.session.add(oplog)
        db.session.commit()
        # 保存电影
        db.session.add(movie)
        db.session.commit()
        flash("修改电影成功", "ok")
        return redirect(url_for("admin.movie_edit", id=movie.id))
    return render_template("admin/movie_edit.html", form=form, movie=movie)


# 添加预告
@admin.route("/preview/add", methods=["GET", "POST"])
@admin_login_rep
def preview_add():
    form = PreviewForm()
    if form.validate_on_submit():
        data = form.data
        file_logo = secure_filename(form.logo.data.filename)
        if not os.path.exists(app.config["UP_DIR"]):  # 文件夹中是否有该文件
            os.makedirs(app.config["UP_DIR"])  # 创建
            os.chmod(app.config["UP_DIR"], "rw")
        logo = change_filename(file_logo)
        form.logo.data.save(app.config["UP_DIR"] + logo)  # 保存
        preview = Preview(
            title=data["title"],
            logo=logo
        )
        # 保存预告操作
        oplog = Oplog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason="添加预告%s" % data["title"]
        )
        db.session.add(oplog)
        db.session.commit()
        # 保存预告
        db.session.add(preview)
        db.session.commit()
        flash("预告添加成功！", "ok")
        return redirect(url_for("admin.preview_add"))
    return render_template("admin/preview_add.html", form=form)


# 预告列表
@admin.route("/preview/list/<int:page>", methods=["GET"])
@admin_login_rep
def preview_list(page=None):
    if page is None:
        page = 1
        # 查询
    page_data = Preview.query.join().filter(
    ).order_by(
        Preview.addtime.desc()
    ).paginate(page=page, per_page=10)
    # print(page_data)
    return render_template("admin/preview_list.html", page_data=page_data)


# 删除预告
@admin.route("/preview/del/<int:id>", methods=["GET"])
@admin_login_rep
def preview_del(id=None):
    preview = Preview.query.filter_by(id=id).first_or_404()
    # 保存记录
    oplog = Oplog(
        admin_id=session['admin_id'],
        ip=request.remote_addr,
        reason="删除预告%s" % preview.title
    )
    db.session.add(oplog)
    db.session.commit()
    # 删除
    db.session.delete(preview)
    db.session.commit()
    flash("删除预告成功！", 'ok')
    # print(page_data)
    return redirect(url_for('admin.preview_list', page=1))


# 修改预告
@admin.route("/preview/edit/<int:id>", methods=["GET", "POST"])
@admin_login_rep
def preview_edit(id=None):
    form = PreviewForm()
    preview = Preview.query.filter_by(id=id).first_or_404()
    if request.method == "GET":
        form.title.data = preview.title
    if form.validate_on_submit():
        data = form.data
        if form.logo.data.filename != "":
            file_logo = secure_filename(form.logo.data.filename)
            preview.logo = change_filename(file_logo)
            form.logo.data.save(app.config["UP_DIR"] + preview.logo)  # 保存
        preview.title = data["title"]
        # 保存操作
        oplog = Oplog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason="修改预告%s" % preview.title
        )
        db.session.add(oplog)
        db.session.commit()
        # 保存修改
        db.session.add(preview)
        db.session.commit()
        flash("修改预告成功！", "ok")
        return redirect(url_for("admin.preview_edit", id=id))
    return render_template("admin/preview_edit.html", form=form, preview=preview)


# 会员列表
@admin.route("/user/list/<int:page>/", methods=["GET"])
@admin_login_rep
def user_list(page=None):
    if page is None:
        page = 1
        # 查询
    page_data = User.query.filter(
    ).order_by(
        User.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/user_list.html", page_data=page_data)


# 查看会员
@admin.route("/user/view/<int:id>/", methods=["GET"])
@admin_login_rep
def user_view(id=None):
    user = User.query.get_or_404(int(id))
    return render_template("admin/user_view.html", user=user)


# 删除会员
@admin.route("/user/del/<int:id>/", methods=["GET"])
@admin_login_rep
def user_del(id=None):
    user = User.query.get_or_404(int(id))
    # 保存操作
    oplog = Oplog(
        admin_id=session['admin_id'],
        ip=request.remote_addr,
        reason="删除会员%s" % user.name
    )
    db.session.add(oplog)
    db.session.commit()
    # 删除
    db.session.delete(user)
    db.session.commit()
    flash('删除会员成功', 'ok')
    return redirect(url_for("admin.user_list", page=1))


# 评论
@admin.route("/comment/list/<int:page>/", methods=["GET"])
@admin_login_rep
def comment_list(page=None):
    if page is None:
        page = 1
        # 查询
    page_data = Comment.query.join(
        Movie
    ).join(
        User
    ).filter(
        Movie.id == Comment.movie_id,
        User.id == Comment.user_id
    ).order_by(
        Comment.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/comment_list.html", page_data=page_data)


# 删除评论
@admin.route("/comment/del/<int:id>/", methods=["GET"])
@admin_login_rep
def comment_del(id=None):
    comment = Comment.query.get_or_404(int(id))
    # 保存操作
    oplog = Oplog(
        admin_id=session['admin_id'],
        ip=request.remote_addr,
        reason="删除评论%s" % comment.content
    )
    db.session.add(oplog)
    db.session.commit()
    # 删除
    db.session.delete(comment)
    db.session.commit()
    flash('删除评论成功', 'ok')
    return redirect(url_for("admin.comment_list", page=1))


# 收藏管理
@admin.route("/moviecol/list/<int:page>/", methods=["GET"])
@admin_login_rep
def moviecol_list(page=None):
    if page == None:
        page = 1
    #     查询
    page_data = Moviecol.query.join(
        Movie
    ).join(
        User
    ).filter(
        Moviecol.movie_id == Movie.id,
        Moviecol.user_id == User.id
    ).order_by(
        Moviecol.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/moviecol_list.html", page_data=page_data)


# 删除收藏
@admin.route("/moviecol/del/<int:id>/", methods=["GET"])
@admin_login_rep
def moviecol_del(id=None):
    moviecol = Moviecol.query.get_or_404(int(id))  # 查询
    # 保存操作
    oplog = Oplog(
        admin_id=session['admin_id'],
        ip=request.remote_addr,
        reason="删除ID为%s的收藏" % moviecol.id
    )
    db.session.add(oplog)
    db.session.commit()
    # 删除
    db.session.delete(moviecol)  # 删除
    db.session.commit()
    flash('删除收藏成功', 'ok')  # 消息闪现
    return redirect(url_for("admin.moviecol_list", page=1))


# 操作日志
@admin.route("/oplog/list/<int:page>/", methods=["GET"])
@admin_login_rep
def oplog_list(page=None):
    if page == None:
        page = 1
    #     查询
    page_data = Oplog.query.join(
        Admin
    ).filter(
        Admin.id == Oplog.admin_id,
    ).order_by(
        Oplog.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/oplog_list.html", page_data=page_data)


# 管理员登录日志
@admin.route("/adminloginlog/list/<int:page>/", methods=["GET"])
@admin_login_rep
def adminloginlog_list(page=None):
    if page == None:
        page = 1
    page_data = Adminlog.query.join(
        Admin
    ).filter(
        Admin.id == Adminlog.admin_id
    ).order_by(
        Adminlog.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/adminloginlog_list.html", page_data=page_data)


@admin.route("/userloginlog/list/<int:page>/", methods=["GET"])
@admin_login_rep
def userloginlog_list(page=None):
    if page == None:
        page = 1
    page_data = Userlog.query.join(
        User
    ).filter(
        User.id == Userlog.user_id
    ).order_by(
        Userlog.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/userloginlog_list.html", page_data=page_data)


# 权限添加
@admin.route("/auth/add/", methods=["GET", "POST"])
@admin_login_rep
def auth_add():
    form = AuthForm()
    if form.validate_on_submit():
        data = form.data
        auth = Auth(
            name=data["name"],
            url=data["url"]
        )
        # 保存操作
        oplog = Oplog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason="添加权限%s" % auth.name
        )
        db.session.add(oplog)
        db.session.commit()
        # 保存
        db.session.add(auth)
        db.session.commit()
        flash("添加权限成功", 'ok')
        return redirect(url_for('admin.auth_add'))
    return render_template("admin/auth_add.html", form=form)


# 权限列表
@admin.route("/auth/list/<int:page>/", methods=["GET"])
@admin_login_rep
def auth_list(page=None):
    if page == None:
        page = 1
    page_data = Auth.query.order_by(
        Auth.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/auth_list.html", page_data=page_data)


# 权限删除
@admin.route("/auth/del/<int:id>/", methods=["GET"])
@admin_login_rep
def auth_del(id=None):
    auth = Auth.query.get_or_404(int(id))  # 查询
    # 保存操作
    oplog = Oplog(
        admin_id=session['admin_id'],
        ip=request.remote_addr,
        reason="删除权限%s" % auth.name
    )
    db.session.add(oplog)
    db.session.commit()
    # 删除
    db.session.delete(auth)  # 删除
    db.session.commit()
    flash('删除收藏成功', 'ok')  # 消息闪现
    return redirect(url_for("admin.auth_list", page=1))


# 编辑权限
@admin.route("/auth/edit/<int:id>/", methods=["GET", "POST"])
@admin_login_rep
def auth_edit(id=None):
    form = AuthForm()
    auth = Auth.query.get_or_404(id)
    if form.validate_on_submit():
        data = form.data
        auth.name = data['name']
        auth.url = data["url"]
        db.session.add(auth)  # 添加
        db.session.commit()  # 保存
        # 保存操作
        oplog = Oplog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason="修改权限%s" % auth.name
        )
        db.session.add(oplog)
        db.session.commit()
        flash('修改标签成功', 'ok')
        return redirect(url_for('admin.auth_edit', id=id))
    return render_template("admin/auth_edit.html", form=form, auth=auth)


# 添加角色
@admin.route("/role/add/", methods=["GET", "POST"])
@admin_login_rep
def role_add():
    form = RoleForm()
    if form.validate_on_submit():
        data = form.data
        role = Role(
            name=data["name"],
            auths=",".join(map(lambda v: str(v),data["auths"]))
                           )
        # 保存操作
        oplog = Oplog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason="添加角色%s" % role.name
        )
        db.session.add(oplog)
        db.session.commit()
        # 保存
        db.session.add(role)
        db.session.commit()
        flash("添加权限成功", 'ok')
        return redirect(url_for('admin.role_add'))
    return render_template("admin/role_add.html", form=form)

#角色列表
@admin.route("/role/list<int:page>/",methods=["GET"])
@admin_login_rep
def role_list(page=None):
    if page==None:
        page=1
    page_data = Role.query.order_by(
        Role.addtime.desc()
    ).paginate(page=page,per_page=10)
    return render_template("admin/role_list.html",page_data=page_data)

#删除角色
@admin.route("/role/del<int:id>/",methods=["GET"])
@admin_login_rep
def role_del(id=None):
    role = Role.query.get_or_404(int(id))
    # 保存操作
    oplog = Oplog(
        admin_id=session['admin_id'],
        ip=request.remote_addr,
        reason="删除角色%s" % role.name
    )
    db.session.add(oplog)
    db.session.commit()
    # 删除
    db.session.delete(role)  # 删除
    db.session.commit()
    flash('删除角色成功', 'ok')  # 消息闪现
    return  redirect(url_for('admin.role_list',page=1))

@admin.route("/role/edit<int:id>/",methods=["GET","POST"])
@admin_login_rep
def role_edit(id=None):
    form = RoleForm()
    role = Role.query.get_or_404(id)
    if request.method=="GET":
        auths = role.auths
        form.auths.data= list(map(lambda v:int(v),auths.split(',')))
    if form.validate_on_submit():
        data = form.data
        role.name = data['name']
        role.auths =",".join(map(lambda v: str(v),data["auths"]))
        db.session.add(role)  # 添加
        db.session.commit()  # 保存
        # 保存操作
        oplog = Oplog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason="修改角色%s" % role.name
        )
        db.session.add(oplog)
        db.session.commit()
        flash('修改角色成功', 'ok')
        return redirect(url_for('admin.role_edit', id=id))
    return render_template("admin/role_edit.html", form=form, role=role)

@admin.route("/admin/add/",methods=["GET","POST"])
@admin_login_rep
def admin_add():
    form = AdminForm()
    from werkzeug.security import generate_password_hash
    if form.validate_on_submit():
        data = form.data
        admin = Admin(
            name=data["name"],
            pwd=generate_password_hash(data["pwd"]),
            role_id=data["role_id"],
            is_super=1
        )
        # 保存操作
        oplog = Oplog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason="添加管理员%s" % admin.name
        )
        db.session.add(oplog)
        db.session.commit()
        # 保存
        db.session.add(admin)
        db.session.commit()
        flash("添加权限成功", 'ok')
        return redirect(url_for('admin.admin_add'))
    return render_template("admin/admin_add.html" ,form=form)


@admin.route("/admin/list/<int:page>/",methods=["GET"])
@admin_login_rep
def admin_list(page=None):
    if page==None:
        page=1
    page_data = Admin.query.join(Role).filter(
        Role.id==Admin.role_id
    ).order_by(
        Admin.addtime.desc()
    ).paginate(page=page,per_page=10)
    return render_template("admin/admin_list.html",page_data=page_data)


