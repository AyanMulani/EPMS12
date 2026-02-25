import os, datetime, io, csv, secrets
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
import pandas as pd

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY','dev-hr-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    "DATABASE_URL",
    "sqlite:///payroll_hr.db"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default='admin')  # superadmin/admin/hr

class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)

class Employee(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    emp_code = db.Column(db.String(64), unique=True, nullable=False)
    first_name = db.Column(db.String(200))
    last_name = db.Column(db.String(200))
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'), nullable=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=True)
    basic_salary = db.Column(db.Float, default=0.0)
    contact = db.Column(db.String(80))
    email = db.Column(db.String(120))
    address = db.Column(db.Text)
    photo = db.Column(db.String(300))
    password_hash = db.Column(db.String(200), nullable=True)
    is_active = db.Column(db.Boolean, default=True)

    department = db.relationship('Department', backref=db.backref('employees', lazy=True))
    role = db.relationship('Role', backref=db.backref('employees', lazy=True))
    
    def get_id(self):
        return str(self.id)

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    check_in = db.Column(db.Time)
    check_out = db.Column(db.Time)
    status = db.Column(db.String(30), default='present')  # present/absent/leave
    employee = db.relationship('Employee', backref=db.backref('attendances', lazy=True))

class LeaveRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    start_date = db.Column(db.Date)
    end_date = db.Column(db.Date)
    reason = db.Column(db.Text)
    status = db.Column(db.String(30), default='pending')  # pending/approved/rejected
    employee = db.relationship('Employee', backref=db.backref('leaves', lazy=True))

class Payroll(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    month = db.Column(db.String(20))
    year = db.Column(db.Integer)
    net_salary = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    employee = db.relationship('Employee', backref=db.backref('payrolls', lazy=True))

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(80))
    action = db.Column(db.String(200))
    ts = db.Column(db.DateTime, default=datetime.datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    # Try admin first, then employee
    user = Admin.query.get(int(user_id))
    if not user:
        user = Employee.query.get(int(user_id))
    return user

def hash_password(password):
    return generate_password_hash(password)

def verify_password(hash_val, password):
    return check_password_hash(hash_val, password)


def log_action(user, action):
    db.session.add(AuditLog(user=user, action=action))
    db.session.commit()

@app.route('/init-db')
def init_db():
    db.create_all()
    # create default admin
    if not Admin.query.filter_by(username='admin').first():
        a = Admin(username='admin', password_hash=hash_password('admin'), role='superadmin')
        db.session.add(a); db.session.commit()
    # sample depts/roles
    if not Department.query.first():
        db.session.add_all([Department(name='HR'), Department(name='IT'), Department(name='Finance')]); db.session.commit()
    if not Role.query.first():
        db.session.add_all([Role(name='Developer'), Role(name='Manager'), Role(name='Accountant')]); db.session.commit()
    return 'initialized'

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        u = request.form.get('username'); p = request.form.get('password')
        user = Admin.query.filter_by(username=u).first()
        if user and verify_password(user.password_hash, p):

            login_user(user)
            log_action(user.username, 'login')
            return redirect(url_for('index'))
        flash('Invalid credentials','danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    if current_user.is_authenticated:
        # Handle both admin and employee users
        if hasattr(current_user, 'username'):
            log_action(current_user.username, 'logout')
        elif hasattr(current_user, 'emp_code'):
            log_action(current_user.emp_code, 'employee_logout')
    logout_user(); return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    employees = Employee.query.order_by(Employee.emp_code.asc()).all()
    payrolls = Payroll.query.order_by(Payroll.id.desc()).limit(50).all()
    return render_template('index.html', employees=employees, payrolls=payrolls, departments=Department.query.all(), roles=Role.query.all())

# Employee CRUD + photo upload
@app.route('/employee/add', methods=['POST'])
@login_required
def add_employee():
    f = request.form
    code = f.get('emp_code','').strip()
    if not code: return jsonify({'ok':False,'error':'emp_code required'}),400
    emp = Employee.query.filter_by(emp_code=code).first()
    photo_file = request.files.get('photo')
    filename = None
    if photo_file and photo_file.filename:
        filename = secure_filename(f"{code}_{secrets.token_hex(6)}_{photo_file.filename}")
        photo_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    if emp:
        # update
        emp.first_name = f.get('first_name'); emp.last_name = f.get('last_name')
        emp.contact = f.get('contact'); emp.email = f.get('email'); emp.address = f.get('address')
        if f.get('department_id'): emp.department_id = int(f.get('department_id'))
        if f.get('role_id'): emp.role_id = int(f.get('role_id'))
        if f.get('basic_salary'): emp.basic_salary = float(f.get('basic_salary') or 0)
        if filename: emp.photo = filename
        db.session.commit()
        log_action(current_user.username, f'update employee {code}')
        return jsonify({'ok':True,'updated':True,'emp_code':code})
    else:
        emp = Employee(emp_code=code, first_name=f.get('first_name'), last_name=f.get('last_name'),
                       contact=f.get('contact'), email=f.get('email'), address=f.get('address'),
                       department_id = int(f.get('department_id')) if f.get('department_id') else None,
                       role_id = int(f.get('role_id')) if f.get('role_id') else None,
                       basic_salary = float(f.get('basic_salary') or 0.0),
                       photo = filename)
        db.session.add(emp); db.session.commit()
        log_action(current_user.username, f'create employee {code}')
        return jsonify({'ok':True,'created':True,'emp_code':code})

@app.route('/employee/search')
@login_required
def search_employee():
    code = request.args.get('code','').strip()
    if not code: return jsonify({'found':False})
    emp = Employee.query.filter_by(emp_code=code).first()
    if not emp:
        try: emp = Employee.query.get(int(code))
        except: emp=None
    if not emp: return jsonify({'found':False})
    data = {
    'id': emp.id,
    'emp_code': emp.emp_code,
    'first_name': emp.first_name,
    'last_name': emp.last_name,
    'department_id': emp.department_id,
    'department_name': emp.department.name if emp.department else '',
    'role_id': emp.role_id,
    'role_name': emp.role.name if emp.role else '',
    'basic_salary': emp.basic_salary,
    'contact': emp.contact,
    'email': emp.email,
    'address': emp.address,
    'photo': emp.photo
}
    return jsonify({'found':True,'emp':data})

# Attendance
@app.route('/attendance/checkin', methods=['POST'])
@login_required
def attendance_checkin():
    code = request.form.get('emp_code','').strip()
    date_str = request.form.get('date') or datetime.date.today().isoformat()
    try: d = datetime.date.fromisoformat(date_str)
    except: d = datetime.date.today()
    emp = Employee.query.filter_by(emp_code=code).first()
    if not emp: return jsonify({'ok':False,'error':'employee not found'}),404
    rec = Attendance.query.filter_by(employee_id=emp.id, date=d).first()
    if not rec: rec = Attendance(employee_id=emp.id, date=d, check_in=datetime.datetime.now().time(), status='present'); db.session.add(rec)
    else: rec.check_in = datetime.datetime.now().time()
    db.session.commit(); log_action(current_user.username, f'checkin {code}')
    return jsonify({'ok':True,'msg':'checked in','date':d.isoformat()})

@app.route('/attendance/checkout', methods=['POST'])
@login_required
def attendance_checkout():
    code = request.form.get('emp_code','').strip()
    date_str = request.form.get('date') or datetime.date.today().isoformat()
    try: d = datetime.date.fromisoformat(date_str)
    except: d = datetime.date.today()
    emp = Employee.query.filter_by(emp_code=code).first()
    if not emp: return jsonify({'ok':False,'error':'employee not found'}),404
    rec = Attendance.query.filter_by(employee_id=emp.id, date=d).first()
    if not rec: return jsonify({'ok':False,'error':'no checkin record'}),400
    rec.check_out = datetime.datetime.now().time(); db.session.commit(); log_action(current_user.username, f'checkout {code}')
    return jsonify({'ok':True,'msg':'checked out','date':d.isoformat()})

# Leave requests
@app.route('/leave/request', methods=['POST'])
@login_required
def leave_request():
    f = request.form
    emp = Employee.query.filter_by(emp_code=f.get('emp_code','').strip()).first()
    if not emp: return jsonify({'ok':False,'error':'employee not found'}),404
    try:
        s = datetime.date.fromisoformat(f.get('start_date')); e = datetime.date.fromisoformat(f.get('end_date'))
    except Exception as exc:
        return jsonify({'ok':False,'error':'invalid dates'}),400
    lr = LeaveRequest(employee_id=emp.id, start_date=s, end_date=e, reason=f.get('reason'))
    db.session.add(lr); db.session.commit(); log_action(current_user.username, f'leave request {emp.emp_code}')
    return jsonify({'ok':True,'id':lr.id})

@app.route('/leave/<int:lid>/decide', methods=['POST'])
@login_required
def leave_decide(lid):
    lr = LeaveRequest.query.get_or_404(lid)
    action = request.form.get('action')
    if action not in ('approved','rejected'): return jsonify({'ok':False,'error':'invalid action'}),400
    lr.status = action; db.session.commit(); log_action(current_user.username, f'leave {action} {lr.id}')
    return jsonify({'ok':True})

# Payroll create (simple)
@app.route('/payroll/create', methods=['POST'])
@login_required
def create_payroll():
    try:
        f = request.form
        code = f.get('emp_code','').strip()
        if not code:
            return jsonify({'ok':False,'error':'Employee code required'}),400
        emp = Employee.query.filter_by(emp_code=code).first()
        if not emp: return jsonify({'ok':False,'error':'employee not found'}),404
        month = f.get('month') or ''; year = int(f.get('year') or 0); net = float(f.get('net_salary') or 0)
        p = Payroll(employee_id=emp.id, month=month, year=year, net_salary=net); db.session.add(p); db.session.commit()
        log_action(current_user.username, f'payroll create {emp.emp_code} {month}/{year}')
        return jsonify({'ok':True,'message':'Payroll created successfully','payroll_id':p.id})
    except Exception as e:
        return jsonify({'ok':False,'error':str(e)}),500

# Reports and exports
@app.route('/export/employees')
@login_required
def export_employees():
    emps = Employee.query.all()
    out = io.StringIO(); w = csv.writer(out); w.writerow(['id','emp_code','first_name','last_name','department','role','basic_salary','contact','email'])
    for e in emps:
        w.writerow([e.id,e.emp_code,e.first_name,e.last_name, e.department.name if e.department else '', e.role.name if e.role else '', e.basic_salary, e.contact,e.email])
    out.seek(0); return send_file(io.BytesIO(out.getvalue().encode('utf-8')), as_attachment=True, download_name='employees.csv', mimetype='text/csv')

@app.route('/export/payrolls')
@login_required
def export_payrolls():
    ps = Payroll.query.all()
    out = io.StringIO(); w = csv.writer(out); w.writerow(['id','employee','month','year','net'])
    for p in ps:
        w.writerow([p.id, p.employee.emp_code, p.month, p.year, p.net_salary])
    out.seek(0); return send_file(io.BytesIO(out.getvalue().encode('utf-8')), as_attachment=True, download_name='payrolls.csv', mimetype='text/csv')

# serve uploads

# Delete employee (removes employee, their attendances, leaves, payrolls, and photo file)
@app.route('/employee/<int:emp_id>/delete', methods=['POST'])
@login_required
def delete_employee(emp_id):
    emp = Employee.query.get_or_404(emp_id)
    # only allow superadmin or hr to delete (admins with any role allowed here)
    # You can adjust permissions if needed (e.g., only superadmin)
    try:
        # remove uploads photo if exists
        if emp.photo:
            try:
                photo_path = os.path.join(app.config['UPLOAD_FOLDER'], emp.photo)
                if os.path.exists(photo_path):
                    os.remove(photo_path)
            except Exception:
                pass
        # delete related records
        Attendance.query.filter_by(employee_id=emp.id).delete()
        LeaveRequest.query.filter_by(employee_id=emp.id).delete()
        Payroll.query.filter_by(employee_id=emp.id).delete()
        # finally delete employee
        db.session.delete(emp)
        db.session.commit()
        log_action(current_user.username, f'delete employee {emp.emp_code}')
        return jsonify({'ok': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/uploads/<path:filename>')
def uploaded_file(filename): return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/static/<path:filename>')
def static_file(filename): return send_from_directory(os.path.join(app.root_path,'static'), filename)

# simple user management page (create additional HR users)
@app.route('/admin/create', methods=['POST'])
@login_required
def admin_create():
    if current_user.role != 'superadmin': return jsonify({'ok':False,'error':'not permitted'}),403
    u = request.form.get('username'); p = request.form.get('password'); r = request.form.get('role') or 'hr'
    if Admin.query.filter_by(username=u).first(): return jsonify({'ok':False,'error':'exists'}),400
    a = Admin(username=u, password_hash=hash_password(p), role=r); db.session.add(a); db.session.commit(); log_action(current_user.username, f'create admin {u}'); return jsonify({'ok':True})

# payroll PDF - admin version (RUPEES)
@app.route('/payroll/<int:pid>/pdf')
@login_required
def payroll_pdf(pid):
    p = Payroll.query.get_or_404(pid); emp = p.employee
    buf = io.BytesIO(); c = canvas.Canvas(buf, pagesize=A4); x=40; y=A4[1]-60
    c.setFont('Helvetica-Bold',14); c.drawString(x,y,'Salary Slip'); y-=20; c.setFont('Helvetica',10)
    for label,val in [('Employee',f'{emp.emp_code} {emp.first_name} {emp.last_name}'),('Month',f'{p.month}/{p.year}'),('Net',str(p.net_salary))]:
        c.drawString(x,y,f'{label}: {val}'); y-=14
    c.showPage(); c.save(); buf.seek(0)
    return send_file(buf, as_attachment=True, download_name=f'pay_{emp.emp_code}_{p.month}_{p.year}.pdf', mimetype='application/pdf')

# helper: password hashing wrapper

# simple API status
@app.route('/status')
def status(): return jsonify({'ok':True,'version':'hr-1.0'})

# ============== EMPLOYEE LOGIN AND DASHBOARD ROUTES ==============

@app.route('/employee/login', methods=['GET','POST'])
def employee_login():
    """Employee login using emp_code and password"""
    if request.method == 'POST':
        emp_code = request.form.get('emp_code', '').strip()
        password = request.form.get('password', '')
        
        emp = Employee.query.filter_by(emp_code=emp_code).first()
        
        if not emp:
            flash('Employee not found', 'danger')
            return render_template('employee_login.html')
        
        if not emp.password_hash:
            flash('Password not set. Please contact admin to set your password.', 'warning')
            return render_template('employee_login.html')
        
        if not verify_password(emp.password_hash, password):
            flash('Invalid password', 'danger')
            return render_template('employee_login.html')
        
        if hasattr(emp, 'is_active') and not emp.is_active:
            flash('Account is deactivated. Contact admin.', 'danger')
            return render_template('employee_login.html')
        
        login_user(emp)
        log_action(emp.emp_code, 'employee_login')
        return redirect(url_for('employee_dashboard'))
    return render_template('employee_login.html')

@app.route('/employee/logout')
def employee_logout():
    if current_user.is_authenticated:
        if hasattr(current_user, 'emp_code'):
            log_action(current_user.emp_code, 'employee_logout')
    logout_user()
    return redirect(url_for('employee_login'))

@app.route('/employee/dashboard')
@login_required
def employee_dashboard():
    """Employee dashboard - only accessible by logged in employees"""
    if not hasattr(current_user, 'emp_code'):
        flash('Access denied. Admin users cannot access employee dashboard.', 'danger')
        return redirect(url_for('index'))
    
    payrolls = Payroll.query.filter_by(employee_id=current_user.id).order_by(Payroll.year.desc(), Payroll.month.desc()).all()
    leaves = LeaveRequest.query.filter_by(employee_id=current_user.id).order_by(LeaveRequest.id.desc()).all()
    
    return render_template('employee_dashboard.html', payrolls=payrolls, leaves=leaves)

@app.route('/employee/payroll/<int:pid>/download')
@login_required
def employee_download_payroll(pid):
    """Employee can download their own salary slip - RUPEES"""
    if not hasattr(current_user, 'emp_code'):
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))
    
    p = Payroll.query.get_or_404(pid)
    
    if p.employee_id != current_user.id:
        flash('Access denied. You can only view your own salary slips.', 'danger')
        return redirect(url_for('employee_dashboard'))
    
    emp = p.employee
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    x = 40
    y = A4[1] - 60
    
    c.setFont('Helvetica-Bold', 16)
    c.drawString(x, y, 'SALARY SLIP')
    y -= 30
    
    c.setFont('Helvetica-Bold', 12)
    c.drawString(x, y, 'Employee Details')
    y -= 20
    c.setFont('Helvetica', 10)
    c.drawString(x, y, f'Employee Code: {emp.emp_code}')
    y -= 14
    c.drawString(x, y, f'Name: {emp.first_name} {emp.last_name}')
    y -= 14
    c.drawString(x, y, f'Department: {emp.department.name if emp.department else "N/A"}')
    y -= 14
    c.drawString(x, y, f'Role: {emp.role.name if emp.role else "N/A"}')
    y -= 25
    
    c.setFont('Helvetica-Bold', 12)
    c.drawString(x, y, 'Salary Details')
    y -= 20
    c.setFont('Helvetica', 10)
    c.drawString(x, y, f'Month/Year: {p.month}/{p.year}')
    y -= 14
    c.drawString(x, y, f'Net Salary: ₹{p.net_salary:.2f}')
    y -= 25
    
    c.setFont('Helvetica-Oblique', 8)
    c.drawString(x, y, 'This is a computer generated salary slip.')
    y -= 10
    c.drawString(x, y, f'Generated on: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    
    c.showPage()
    c.save()
    buf.seek(0)
    
    return send_file(buf, as_attachment=True, download_name=f'salary_slip_{emp.emp_code}_{p.month}_{p.year}.pdf', mimetype='application/pdf')

@app.route('/employee/leave/request', methods=['POST'])
@login_required
def employee_leave_request():
    """Employee submits leave request"""
    if not hasattr(current_user, 'emp_code'):
        return jsonify({'ok': False, 'error': 'Access denied'}), 403
    
    f = request.form
    try:
        start_date = datetime.date.fromisoformat(f.get('start_date'))
        end_date = datetime.date.fromisoformat(f.get('end_date'))
    except Exception:
        return jsonify({'ok': False, 'error': 'Invalid dates format'}), 400
    
    if end_date < start_date:
        return jsonify({'ok': False, 'error': 'End date cannot be before start date'}), 400
    
    reason = f.get('reason', '')
    
    lr = LeaveRequest(employee_id=current_user.id, start_date=start_date, end_date=end_date, reason=reason, status='pending')
    db.session.add(lr)
    db.session.commit()
    log_action(current_user.emp_code, 'leave_request submitted')
    
    return jsonify({'ok': True, 'id': lr.id, 'message': 'Leave request submitted successfully'})

@app.route('/employee/set-password', methods=['POST'])
@login_required
def employee_set_password():
    """Allow employee to set their password"""
    if not hasattr(current_user, 'emp_code'):
        return jsonify({'ok': False, 'error': 'Access denied'}), 403
    
    password = request.form.get('password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    if not password or len(password) < 4:
        return jsonify({'ok': False, 'error': 'Password must be at least 4 characters'}), 400
    
    if password != confirm_password:
        return jsonify({'ok': False, 'error': 'Passwords do not match'}), 400
    
    current_user.password_hash = hash_password(password)
    db.session.commit()
    log_action(current_user.emp_code, 'password_set')
    
    return jsonify({'ok': True, 'message': 'Password set successfully'})

@app.route('/employee/check-password', methods=['GET'])
@login_required
def employee_check_password():
    """Check if employee has set a password"""
    if not hasattr(current_user, 'emp_code'):
        return jsonify({'has_password': False})
    
    has_password = current_user.password_hash is not None and current_user.password_hash != ''
    return jsonify({'has_password': has_password})

# Admin route to set employee password
@app.route('/admin/set-employee-password', methods=['POST'])
@login_required
def admin_set_employee_password():
    """Admin can set password for employees"""
    f = request.form
    emp_code = f.get('emp_code', '').strip()
    password = f.get('password', '')
    
    if not emp_code or not password:
        return jsonify({'ok': False, 'error': 'Employee code and password are required'}), 400
    
    emp = Employee.query.filter_by(emp_code=emp_code).first()
    if not emp:
        return jsonify({'ok': False, 'error': 'Employee not found'}), 404
    
    try:
        emp.password_hash = generate_password_hash(password)
        db.session.commit()
        log_action(current_user.username, f'set_password for employee {emp_code}')
        return jsonify({'ok': True, 'message': f'Password set successfully for {emp_code}'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'ok': False, 'error': str(e)}), 500

# Debug route to check employee password status
@app.route('/debug/employee/<emp_code>')
def debug_employee(emp_code):
    """Debug endpoint to check employee password status"""
    emp = Employee.query.filter_by(emp_code=emp_code).first()
    if not emp:
        return jsonify({'error': 'Employee not found'}), 404
    
    return jsonify({
        'id': emp.id,
        'emp_code': emp.emp_code,
        'first_name': emp.first_name,
        'password_hash': emp.password_hash,
        'password_hash_length': len(emp.password_hash) if emp.password_hash else 0,
        'is_active': emp.is_active
    })

# Simple page for admin to manage employee passwords
@app.route('/admin/employee-passwords')
@login_required
def admin_employee_passwords():
    """Page for admin to set employee passwords"""
    employees = Employee.query.order_by(Employee.emp_code.asc()).all()
    return render_template('admin_employee_passwords.html', employees=employees)



# Admin leave management
@app.route('/admin/leave-requests')
@login_required
def admin_leave_requests():
    """Page for admin to view and manage leave requests"""
    leave_requests = LeaveRequest.query.order_by(LeaveRequest.id.desc()).all()
    return render_template('admin_leave_requests.html', leave_requests=leave_requests)

@app.route('/admin/leave/<int:lid>/approve', methods=['POST'])
@login_required
def admin_approve_leave(lid):
    """Admin approves a leave request"""
    try:
        lr = LeaveRequest.query.get_or_404(lid)
        lr.status = 'approved'
        db.session.commit()
        user_name = getattr(current_user, 'username', 'admin')
        log_action(user_name, f'approve leave {lid}')
        flash(f'Leave request approved for {lr.employee.emp_code}', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('admin_leave_requests'))

@app.route('/admin/leave/<int:lid>/reject', methods=['POST'])
@login_required
def admin_reject_leave(lid):
    """Admin rejects a leave request"""
    try:
        lr = LeaveRequest.query.get_or_404(lid)
        lr.status = 'rejected'
        db.session.commit()
        user_name = getattr(current_user, 'username', 'admin')
        log_action(user_name, f'reject leave {lid}')
        flash(f'Leave request rejected for {lr.employee.emp_code}', 'warning')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('admin_leave_requests'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
