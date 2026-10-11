import os,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
os.environ['AES256_KEY_HEX']='a'*64
from app import app,db,User
def test_injection_and_access():
 app.config['TESTING']=True
 with app.app_context():db.session.query(User).delete();db.session.commit()
 with app.test_client() as c:
  assert c.post('/api/register',json={'username':'alice','password':'strongpassword123','note':'private'}).status_code==201
  assert c.post('/api/login',json={'username':"alice' OR 1=1 --",'password':'x'}).status_code==401
  assert c.get('/api/note').status_code==403
  cap=c.post('/api/login',json={'username':'alice','password':'strongpassword123'}).json['capability']
  assert c.get('/api/note',headers={'X-Capability':cap}).json['note']=='private'
