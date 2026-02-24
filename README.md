HR Payroll - README

This expanded HR payroll package includes:
- Departments and Roles
- Employee photo upload (stored in uploads/)
- Payroll create + PDF payslip generation
- Export employees and payrolls to CSV
- Audit log of actions<i<img width="976" height="291" alt="Screenshot 2026-02-17 194921" src="https://github.com/user-attachments/assets/5b7d1361-7732-42f5-9fb3-98966f39a52a" />
mg width="1919" height="962" alt="Screenshot 2026-02-17 195228" src="https://github.com/user-attachments/assets/188e1712-cbfa-4d2e-b43d-7c3<img width="1911" height="829" alt="Screenshot 2026-02-17 194805" src="https://github.com/user-attachments/assets/c860571a-5b16-4af0-ab9d-d3d4e1835700" />
a35a83796" />

- Admin users with hashed passwords
- Simple web UI (Boot<img width="1761" height="966" alt="Screenshot 2026-02-17 195338" src="https://github.com/user-attachments/assets/fdc25a2e-dd01-4baf-8b34-d3b3c589e585" />
strap) with client-side calculator and receipt preview
- Sample data created via /init-db

Important:
- Reference GUI image included in static/reference_gui.jpg (original path: /mnt/data/gu.jpg)
- To run:
  1. python -m venv venv
  2. .\\venv\\Scripts\\Activate
  3. pip install -r requirements.txt
  4. python app.py
  5. Visit: http://127.0.0.1:5000/init-db to create admin/sample data (admin/admin)
  6. Login: http://127.0.0.1:5000/login (admin/admin)

Files:
- app.py
- templates/login.html, templates/index.html
- static/style.css, static/main.js, static/reference_gui.jpg
- requirements.txt

Uploads are saved to uploads/ directory inside project folder.

