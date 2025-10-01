from flask import Flask, render_template, request, redirect, url_for, send_from_directory, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os, uuid
import requests
import smtplib
import random
from email.mime.text import MIMEText
from datetime import datetime,timedelta

app = Flask(__name__)
app.secret_key = 'mgmq owhb lfet lfsd'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['IMAGE_FOLDER'] = 'static/images'

db = SQLAlchemy(app)

# === Models ===
class TopupRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    processed_at = db.Column(db.DateTime, nullable=True)
    user = db.relationship('User', backref='topups')
    approved = db.Column(db.Boolean, default=False)

class WithdrawalRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    bank_name = db.Column(db.String(100), nullable=True)
    account_number = db.Column(db.String(50), nullable=True)
    account_holder = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    processed_at = db.Column(db.DateTime, nullable=True)  # Thêm dòng này
    user = db.relationship('User', backref='withdrawals')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True)
    is_verified = db.Column(db.Boolean, default=False)
    wallet = db.Column(db.Integer, default=0)
    is_admin = db.Column(db.Boolean, default=False)



class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    description = db.Column(db.Text)
    filename = db.Column(db.String(200))
    image_filename = db.Column(db.String(200))
    price = db.Column(db.Integer, default=0)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # người bán
    owner = db.relationship('User', backref='games_uploaded')   # quan hệ ORM

class Purchase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    game_id = db.Column(db.Integer, db.ForeignKey('game.id'))
    price = db.Column(db.Integer)

class Voucher(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    used = db.Column(db.Boolean, default=False)
    value = db.Column(db.Integer, nullable=False)  # Giá trị nạp
    amount = db.Column(db.Integer, nullable=False)  # Số lượng còn lại
    expires_at = db.Column(db.DateTime, nullable=True)

class UserVoucher(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    voucher_id = db.Column(db.Integer, db.ForeignKey('voucher.id'))
    used = db.Column(db.Boolean, default=False)
    used_at = db.Column(db.DateTime, nullable=True)

# === Helper ===
def send_email_brevo(to_email, subject, content):
    url = "https://api.brevo.com/v3/smtp/email"
    api_key = "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"  # 🔑 đổi thành API key lấy trên Brevo

    payload = {
        "sender": {"name": "Indie Game", "email": "trandangconcho@gmail.com"},  # đổi email đã xác minh
        "to": [{"email": to_email}],
        "subject": subject,
        "htmlContent": f"<p>{content}</p>"
    }

    headers = {
        "accept": "application/json",
        "api-key": api_key,
        "content-type": "application/json"
    }

    try:
        response = requests.post(url, json=payload, headers=headers)
        print("[Brevo] Response:", response.json())
        return True
    except Exception as e:
        print("[Brevo] Error:", e)
        return False

def has_purchased(user_id, game_id):
    return Purchase.query.filter_by(user_id=user_id, game_id=game_id).first() is not None

# === Routes ===
@app.route('/')
def index():
    search = request.args.get('search', '').lower()
    price_range = request.args.get('price_range')
    games = Game.query.all()

    if search:
        games = [game for game in games if search in game.name.lower()]

    if price_range:
        if price_range == 'free':
            games = [game for game in games if game.price == 0]
        elif price_range == 'lt20':
            games = [game for game in games if 0 < game.price < 20000]
        elif price_range == '20to50':
            games = [game for game in games if 20000 <= game.price <= 50000]
        elif price_range == 'gt50':
            games = [game for game in games if game.price > 50000]

    username = None
    wallet = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            username = user.username
            wallet = user.wallet

    return render_template('index.html', games=games, username=username, wallet=wallet)


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['game_name']
        description = request.form['description']
        price = int(request.form['price'])
        file = request.files['game_file']
        image = request.files['game_image']
        owner_id=session['user_id']

        filename = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
        image_filename = f"{uuid.uuid4().hex}_{secure_filename(image.filename)}"

        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        image.save(os.path.join(app.config['IMAGE_FOLDER'], image_filename))

        new_game = Game(name=name, description=description, filename=filename, image_filename=image_filename, price=price,owner_id=session['user_id'])
        db.session.add(new_game)
        db.session.commit()
        return redirect(url_for('index'))

    return render_template('upload.html')

@app.route('/game/<int:game_id>')
def game(game_id):
    game = Game.query.get_or_404(game_id)
    user_has_purchased = 'user_id' in session and has_purchased(session['user_id'], game.id)
    return render_template('game.html', game=game, user_has_purchased=user_has_purchased)

@app.route('/buy/<int:game_id>', methods=['POST'])
def buy_game(game_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    buyer = User.query.get(session['user_id'])
    game = Game.query.get_or_404(game_id)

    if has_purchased(buyer.id, game.id):
        flash("Đã mua game này rồi.")
        return redirect(url_for('index'))

    if buyer.wallet < game.price:
        flash("Không đủ xu trong ví.", "danger")
        return redirect(url_for('index'))

    # Trừ tiền người mua
    buyer.wallet -= game.price

    # Tìm người bán
    seller = User.query.get(game.owner_id)
    if seller and seller.id != buyer.id:  # không tự mua của chính mình
        seller.wallet += int(game.price * 0.9)  # chia hoa hồng 90% nếu muốn
        # hoặc dùng: seller.wallet += game.price  # nếu không thu phí
    admin = User.query.filter_by(is_admin=True).first()
    if game.owner_id == buyer.id:
        flash("Không thể mua game của chính bạn.", "danger")
        return redirect(url_for('game', game_id=game.id))

    if admin:
        admin.wallet += int(game.price * 0.1)

    # Ghi lại purchase
    purchase = Purchase(user_id=buyer.id, game_id=game.id, price=game.price)
    db.session.add(purchase)
    db.session.commit()
    flash("Mua thành công.", "success")
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = db.session.get(User, session['user_id'])
    if not user:
        return redirect(url_for('login'))

    return render_template('dashboard.html', user=user)
@app.route('/download/<filename>')
def download(filename):
    game = Game.query.filter_by(filename=filename).first()
    if not game:
        return "Game không tồn tại", 404
    if 'user_id' not in session or not has_purchased(session['user_id'], game.id):
        flash('Cần mua game để tải.', 'warning')
        return redirect(url_for('game', game_id=game.id))
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        flash('Sai tên hoặc mật khẩu')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm = request.form.get('confirm')
        email = request.form.get('email')

        # 1. Kiểm tra mật khẩu khớp
        if password != confirm:
            flash('Mật khẩu không khớp.', 'danger')
            return redirect(url_for('register'))

        # 2. Kiểm tra username đã tồn tại chưa
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Tên người dùng đã tồn tại.', 'danger')
            return redirect(url_for('register'))

        # 3. Tạo OTP
        otp = str(random.randint(100000, 999999))

        # 4. Lưu vào session để xác minh sau
        session['otp'] = otp
        session['otp_expire'] = (datetime.utcnow() + timedelta(minutes=5)).timestamp()
        session['otp_data'] = {
            'username': username,
            'email': email,
            'password': generate_password_hash(password)  # Lưu hash mật khẩu
        }

        # 5. Gửi email qua Brevo
        if send_email_brevo(email, "Xác nhận đăng ký Indie", f"Mã OTP của bạn là: {otp}"):
            flash('Mã OTP đã được gửi tới email của bạn.', 'info')
            return redirect(url_for('verify_email'))
        else:
            flash('Không thể gửi mã OTP. Vui lòng thử lại sau.', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')


@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    if request.method == 'POST':
        user_otp = request.form.get('otp')
        correct_otp = session.get('otp')
        otp_expire = session.get('otp_expire')  # ✅ lấy hạn dùng
        data = session.get('otp_data')

        # ✅ check hết hạn
        if not otp_expire or datetime.utcnow().timestamp() > otp_expire:
            flash("Mã OTP đã hết hạn. Vui lòng đăng ký lại.", "danger")
            session.pop('otp', None)
            session.pop('otp_expire', None)
            session.pop('otp_data', None)
            return redirect(url_for('register'))

        if correct_otp and data and user_otp == correct_otp:
            new_user = User(
                username=data['username'],
                password=data['password'],
                email=data['email'],
                is_verified=True
            )
            db.session.add(new_user)
            db.session.commit()

            # Dọn session sau khi xong
            session.pop('otp', None)
            session.pop('otp_expire', None)   # ✅ clear luôn
            session.pop('otp_data', None)

            flash('Xác minh thành công! Tài khoản đã được tạo.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Mã OTP không đúng.', 'danger')

    return render_template('verify_email.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/redeem_voucher', methods=['POST'])
def redeem_voucher():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    code = request.form['voucher_code'].strip()
    voucher = Voucher.query.filter_by(code=code).first()

    if not voucher:
        flash("❌ Mã voucher không tồn tại.")
    elif voucher.expires_at and voucher.expires_at < datetime.utcnow():
        flash("⚠️ Mã voucher đã hết hạn.")
    elif voucher.amount <= 0:
        flash("⚠️ Mã voucher đã hết lượt sử dụng.")
    else:
        user.wallet += voucher.value
        voucher.amount -= 1
        db.session.commit()
        flash(f"✅ Nhận {voucher.value} VNĐ thành công từ voucher!")

    return redirect(url_for('index'))

@app.route('/create-test-user')
def create_test_user():
    if not User.query.filter_by(username='testuser').first():
        hashed_pw = generate_password_hash('1234')
        user = User(username='testuser', password=hashed_pw, wallet=100000)
        db.session.add(user)
        db.session.commit()
        return "Tạo user test thành công!"
    return "User test đã tồn tại!"


@app.route('/create-test-voucher')
def create_test_voucher():
    from datetime import datetime, timedelta
    if not Voucher.query.filter_by(code='INDIE2025').first():
        voucher = Voucher(
            code='INDIE2025',
            value=50000,
            amount=10,
            expires_at=datetime.now() + timedelta(days=30)
        )
        db.session.add(voucher)
        db.session.commit()
        return 'Đã tạo voucher test INDIE2025!'
    return 'Voucher đã tồn tại.'
@app.route('/use-voucher', methods=['POST'])
def use_voucher():
    if 'user_id' not in session:
        return "Bạn phải đăng nhập để sử dụng voucher.", 401

    code = request.form.get('code')  # mã từ form nhập
    voucher = Voucher.query.filter_by(code=code).first()

    if not voucher:
        return "Voucher không tồn tại.", 404

    if voucher.amount <= 0:
        return "Voucher đã hết lượt sử dụng.", 400


    if voucher.expires_at and voucher.expires_at < datetime.utcnow():
        return "Voucher đã hết hạn.", 400

    user = User.query.get(session['user_id'])
    user.wallet += voucher.value
    voucher.used = True
    voucher.amount -= 1

    db.session.commit()
    return f"Đã cộng {voucher.value} vào tài khoản của bạn!"

@app.route('/wallet')
def wallet():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template('wallet.html', user=user)

@app.route('/create-admin')
def create_admin():
    if not User.query.filter_by(username='admin').first():
        hashed_pw = generate_password_hash('admin123')
        admin = User(username='admin', password=hashed_pw, wallet=10000000, is_admin=True)
        db.session.add(admin)
        db.session.commit()
        return "Admin đã được tạo!"
    return "Admin đã tồn tại."


@app.route('/stats/<username>')
def stats(username):
    user = User.query.filter_by(username=username).first()

    if not user:
        return "Người dùng không tồn tại", 404

    user_games = Game.query.filter_by(owner_id=user.id).all()

    total_sales = 0
    total_revenue = 0
    admin_fee = 0
    game_stats = []

    for game in user_games:
        purchases = Purchase.query.filter_by(game_id=game.id).all()
        num_purchases = len(purchases)
        revenue = num_purchases * game.price * 0.9
        fee = num_purchases * game.price * 0.1

        total_sales += num_purchases
        total_revenue += revenue
        admin_fee += fee

        game_stats.append({
            'title': game.name,             # Đổi 'name' → 'title'
            'sold': num_purchases,          # Đổi 'sales' → 'sold'
            'income': revenue + fee,        # Tổng doanh thu
            'to_owner': revenue,            # Doanh thu chủ game
            'to_admin': fee                 # Phí admin
        })

    return render_template(
        'stats_public.html',
        username=user.username,
        total_sales=total_sales,
        total_revenue=total_revenue,
        admin_fee=admin_fee,
        stats=game_stats
    )

@app.route('/withdraw', methods=['GET', 'POST'])
def withdraw():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        try:
            amount = int(request.form['amount'])
            bank_name = request.form['bank_name'].strip()
            account_number = request.form['account_number'].strip()
            account_holder = request.form['account_holder'].strip()

            # Kiểm tra dữ liệu
            if amount < 50000:
                flash('Số tiền tối thiểu để rút là 50.000 VNĐ.', 'danger')
            elif amount > user.wallet:
                flash('Số dư không đủ để rút số tiền này.', 'danger')
            elif not bank_name or not account_number or not account_holder:
                flash('Vui lòng điền đầy đủ thông tin ngân hàng.', 'danger')
            else:
                new_request = WithdrawalRequest(
                    user_id=user.id,
                    amount=amount,
                    bank_name=bank_name,
                    account_number=account_number,
                    account_holder=account_holder,
                    status='pending'
                )
                db.session.add(new_request)
                db.session.commit()

                flash('Đã gửi yêu cầu rút tiền. Admin sẽ xử lý trong 1 => 7 ngày. Nếu sau 7 ngày chưa nhận tiền, hãy liên hệ Facebook!', 'success')
                return redirect(url_for('index'))  # ✅ dòng này cần thụt vào đúng vị trí

        except ValueError:
            flash('Dữ liệu nhập vào không hợp lệ.', 'danger')

    return render_template('withdraw.html', user=user)  # hoặc form template của bạn


    # Gợi ý: lấy thông tin đã từng nhập nếu có
    previous_request = WithdrawalRequest.query.filter_by(user_id=user.id).order_by(WithdrawalRequest.id.desc()).first()
    bank_name = previous_request.bank_name if previous_request else ''
    account_number = previous_request.account_number if previous_request else ''
    account_holder = previous_request.account_holder if previous_request else ''

    return render_template(
        'withdraw.html',
        bank_name=bank_name,
        account_number=account_number,
        account_holder=account_holder
    )



@app.route('/admin/withdrawals')
def view_withdrawals():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    admin = User.query.get(session['user_id'])
    if not admin.is_admin:
        return "Không có quyền.", 403

    pending_requests = WithdrawalRequest.query.order_by(WithdrawalRequest.created_at.desc()).all()
    return render_template('admin_withdrawals.html', requests=pending_requests)


@app.route('/admin/withdrawals/confirm/<int:req_id>')
def confirm_withdrawal(req_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    admin = User.query.get(session['user_id'])
    if not admin.is_admin:
        return "Không có quyền.", 403

    req = WithdrawalRequest.query.get_or_404(req_id)
    if req.status != 'pending':
        return "Yêu cầu đã xử lý.", 400

    user = User.query.get(req.user_id)
    if user.wallet >= req.amount:
        user.wallet -= req.amount
        req.status = 'approved'
        req.processed_at = datetime.utcnow()
        db.session.commit()
        flash(f"✅ Đã xử lý rút {req.amount} VNĐ cho {user.username}.")
    else:
        flash("⚠️ Ví không đủ tiền.", 'danger')

    return redirect(url_for('view_withdrawals'))

@app.route('/topup', methods=['GET', 'POST'])
def topup():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        try:
            amount = int(request.form['amount'])
            if amount <= 0:
                flash("Số tiền không hợp lệ.", "danger")
            else:
                topup = TopupRequest(user_id=user.id, amount=amount)
                db.session.add(topup)
                db.session.commit()
                flash("✅ Yêu cầu nạp tiền đã được gửi, vui lòng chờ admin duyệt!", "success")
                return redirect(url_for('index'))
        except ValueError:
            flash("Vui lòng nhập số tiền hợp lệ.", "danger")

    return render_template('topup.html')

@app.route('/admin/topups')
def view_topups():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    admin = User.query.get(session['user_id'])
    if not admin.is_admin:
        return "Không có quyền.", 403

    topup_requests = TopupRequest.query.order_by(TopupRequest.created_at.desc()).all()
    return render_template('admin_topups.html', requests=topup_requests)

@app.route('/admin/topup/confirm/<int:req_id>', methods=['GET','POST'])
def confirm_topup(req_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    admin = User.query.get(session['user_id'])
    if not admin.is_admin:
        return "Không có quyền.", 403

    req = TopupRequest.query.get(req_id)
    if not req or req.status != 'pending':
        return "Yêu cầu không hợp lệ hoặc đã xử lý.", 400

    req.status = 'approved'
    user = User.query.get(req.user_id)
    user.wallet += req.amount
    req.status = 'approved'
    req.processed_at = datetime.utcnow()
    db.session.commit()

    flash("Duyệt thành công!", "success")
    return redirect(url_for('view_topups'))

@app.route('/admin/users')
def admin_users():
    print("Session:", session)  # dòng này để debug
    if 'user_id' not in session:
        return redirect(url_for('login'))

    admin = User.query.get(session['user_id'])
    if not admin or not admin.is_admin:
        return "Không có quyền.", 403

    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/check_admin')
def check_admin():
    if 'user_id' not in session:
        return 'Chưa đăng nhập'
    
    user = User.query.get(session['user_id'])
    return f'User ID: {user.id}, is_admin: {user.is_admin}'


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    admin = User.query.get(session['user_id'])
    if not admin or not admin.is_admin:
        return "Không có quyền.", 403

    # ✅ Không cho admin tự xóa mình
    if admin.id == user_id:
        flash("Không thể xóa chính bạn khi đang đăng nhập.", "danger")
        return redirect(url_for('admin_users'))

    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash(f'Đã xóa tài khoản của {user.username}.', 'success')
    else:
        flash('Không tìm thấy người dùng.', 'danger')

    return redirect(url_for('admin_users'))


@app.context_processor
def inject_user():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        return dict(current_user=user)
    return dict(current_user=None)

@app.route('/googlee88d196767f03d0a.html')
def serve_google_file():
    return send_from_directory('.', 'googlee88d196767f03d0a.html')

# === Init App ===
# === Init App ===
with app.app_context():
    db.create_all()
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['IMAGE_FOLDER'], exist_ok=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
