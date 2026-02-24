// Main JS: reuse and enhance behavior for HR features
document.addEventListener('DOMContentLoaded', function(){
  // employee save via form submit
  var empForm = document.getElementById('empForm');
  if(empForm){
    empForm.addEventListener('submit', function(ev){
      ev.preventDefault();
      var fd = new FormData(empForm);
      fetch('/employee/add', {method:'POST', body: fd}).then(r=>r.json()).then(j=>{
if(j.ok){

  var empCode = document.getElementById('emp_code').value;
  var firstName = document.getElementById('first_name').value;

  var deptSelect = document.getElementById('department_id');
  var dept = deptSelect.options[deptSelect.selectedIndex].text;

  if(window.saveToFirebase){
      window.saveToFirebase(empCode, firstName, dept);
  }

  document.getElementById('save_status').innerText = 'Saved: '+j.emp_code;
  setTimeout(()=>location.reload(),700);
}        else alert('Error: '+(j.error||'unknown'));
      }).catch(e=>alert('Save error: '+e));
    });
  }
  // search button
  // search button
var search = document.getElementById('search');
if(search) search.addEventListener('click', function(){
  var code = document.getElementById('emp_code').value.trim();
  if(!code) return alert('Enter code');
  fetch('/employee/search?code='+encodeURIComponent(code)).then(r=>r.json()).then(j=>{
    if(!j.found) return alert('Not found');
    var e=j.emp;

    ['first_name','last_name','contact','email','address','basic_salary']
    .forEach(function(k){
      if(document.getElementById(k))
        document.getElementById(k).value = e[k]||'';
    });

    document.getElementById('pay_emp_code').value = e.emp_code||'';

    // 🔥 ADD THESE 4 LINES
    if(document.getElementById('department_id'))
        document.getElementById('department_id').value = e.department_id || '';

    if(document.getElementById('role_id'))
        document.getElementById('role_id').value = e.role_id || '';

    document.getElementById('save_status').innerText = 'Loaded '+e.emp_code;
  });
});
  // table row click
  document.querySelectorAll('#emp_table tbody tr').forEach(function(row){ row.addEventListener('click', function(){ document.getElementById('emp_code').value=this.cells[0].innerText.trim(); document.getElementById('search').click(); }); });
  // calculator
  var screen = document.getElementById('calc_screen');
  document.querySelectorAll('.calc-key').forEach(function(b){ b.addEventListener('click', function(){ screen.value += this.innerText; }); });
  document.querySelectorAll('.calc-op').forEach(function(b){ b.addEventListener('click', function(){ screen.value += ' ' + this.innerText + ' '; }); });
  var clearCalc = document.getElementById('calc-clear'); if(clearCalc) clearCalc.addEventListener('click', function(){ screen.value = ''; });
  var eq = document.getElementById('calc-eq'); if(eq) eq.addEventListener('click', function(){ try{ screen.value = eval(screen.value||'0'); }catch(e){ screen.value='Err'; } });
  // calculate payroll client-side
  var calcBtn = document.getElementById('calc_btn');
  if(calcBtn) calcBtn.addEventListener('click', function(){
    var basic = parseFloat(document.getElementById('basic_salary').value||0);
    var total_days = parseInt(document.getElementById('total_days').value||30);
    var absents = parseInt(document.getElementById('absents').value||0);
    var medical = parseFloat(document.getElementById('medical').value||0);
    var convey = parseFloat(document.getElementById('conveyance')?document.getElementById('conveyance').value:0);
    var pf = parseFloat(document.getElementById('pf').value||0);
    var overtime = parseFloat(document.getElementById('overtime').value||0);
    var deducted = parseFloat(document.getElementById('deducted').value||0);
    var added = parseFloat(document.getElementById('added').value||0);
    var worked = Math.max(total_days-absents,0);
    var prorated = total_days? (basic/total_days)*worked : basic;
    var hourly = basic/(total_days*8||1);
    var otpay = overtime*hourly*1.5;
    var gross = prorated + medical + convey + otpay + added;
    var net = gross - pf - deducted;
    document.getElementById('net_salary').value = net.toFixed(2);
    document.getElementById('receipt_area').innerText = 'Employee: '+document.getElementById('emp_code').value + '\nName: '+document.getElementById('first_name').value + ' ' + document.getElementById('last_name').value + '\nNet: '+net.toFixed(2);
  });
  // print and download PDF guidance
  var pr = document.getElementById('print_receipt'); if(pr) pr.addEventListener('click', function(){ window.print(); });
  var dl = document.getElementById('download_pdf'); if(dl) dl.addEventListener('click', function(e){ e.preventDefault(); alert('Save payroll, then click PDF in payroll records to download.'); });
});


// delete employee handler
document.querySelectorAll('.emp-delete').forEach(function(btn){
  btn.addEventListener('click', function(){
    var id = this.getAttribute('data-id');
    if(!confirm('Delete employee? This will remove all payrolls, attendance and photo.')) return;
    fetch('/employee/' + id + '/delete', { method: 'POST', headers: {'Content-Type':'application/json'} })
      .then(r=>r.json()).then(j=>{
        if(j.ok){ alert('Deleted'); location.reload(); }
        else alert('Delete failed: '+(j.error||'unknown'));
      }).catch(e=>alert('Delete error: '+e));
  });
});

